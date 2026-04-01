// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced PCIe Subsystem
// Configuration Space, MSI/MSI-X, SR-IOV, AER, ACS, ASPM, Hotplug

const std = @import("std");

// ============================================================================
// PCI Configuration Space
// ============================================================================

pub const PCI_CFG_VENDOR_ID: u8 = 0x00;
pub const PCI_CFG_DEVICE_ID: u8 = 0x02;
pub const PCI_CFG_COMMAND: u8 = 0x04;
pub const PCI_CFG_STATUS: u8 = 0x06;
pub const PCI_CFG_REV_ID: u8 = 0x08;
pub const PCI_CFG_PROG_IF: u8 = 0x09;
pub const PCI_CFG_SUBCLASS: u8 = 0x0A;
pub const PCI_CFG_CLASS: u8 = 0x0B;
pub const PCI_CFG_CACHE_LINE: u8 = 0x0C;
pub const PCI_CFG_LATENCY: u8 = 0x0D;
pub const PCI_CFG_HEADER_TYPE: u8 = 0x0E;
pub const PCI_CFG_BIST: u8 = 0x0F;
pub const PCI_CFG_BAR0: u8 = 0x10;
pub const PCI_CFG_BAR1: u8 = 0x14;
pub const PCI_CFG_BAR2: u8 = 0x18;
pub const PCI_CFG_BAR3: u8 = 0x1C;
pub const PCI_CFG_BAR4: u8 = 0x20;
pub const PCI_CFG_BAR5: u8 = 0x24;
pub const PCI_CFG_CARDBUS_CIS: u8 = 0x28;
pub const PCI_CFG_SUBSYS_VENDOR: u8 = 0x2C;
pub const PCI_CFG_SUBSYS_ID: u8 = 0x2E;
pub const PCI_CFG_ROM_BASE: u8 = 0x30;
pub const PCI_CFG_CAP_PTR: u8 = 0x34;
pub const PCI_CFG_INT_LINE: u8 = 0x3C;
pub const PCI_CFG_INT_PIN: u8 = 0x3D;
pub const PCI_CFG_MIN_GNT: u8 = 0x3E;
pub const PCI_CFG_MAX_LAT: u8 = 0x3F;

// PCI Command register bits
pub const PCI_CMD_IO_SPACE: u16 = 1 << 0;
pub const PCI_CMD_MEM_SPACE: u16 = 1 << 1;
pub const PCI_CMD_BUS_MASTER: u16 = 1 << 2;
pub const PCI_CMD_SPECIAL_CYCLES: u16 = 1 << 3;
pub const PCI_CMD_MWI_ENABLE: u16 = 1 << 4;
pub const PCI_CMD_VGA_PALETTE: u16 = 1 << 5;
pub const PCI_CMD_PARITY_ERROR: u16 = 1 << 6;
pub const PCI_CMD_SERR_ENABLE: u16 = 1 << 8;
pub const PCI_CMD_FAST_B2B: u16 = 1 << 9;
pub const PCI_CMD_INT_DISABLE: u16 = 1 << 10;

// PCI Status register bits
pub const PCI_STS_INT_STATUS: u16 = 1 << 3;
pub const PCI_STS_CAP_LIST: u16 = 1 << 4;
pub const PCI_STS_66MHZ: u16 = 1 << 5;
pub const PCI_STS_FAST_B2B: u16 = 1 << 7;
pub const PCI_STS_PARITY_ERROR: u16 = 1 << 8;
pub const PCI_STS_DEVSEL_MASK: u16 = 0x3 << 9;
pub const PCI_STS_SIG_TARGET_ABORT: u16 = 1 << 11;
pub const PCI_STS_RCV_TARGET_ABORT: u16 = 1 << 12;
pub const PCI_STS_RCV_MASTER_ABORT: u16 = 1 << 13;
pub const PCI_STS_SIG_SYS_ERROR: u16 = 1 << 14;
pub const PCI_STS_PARITY_DETECT: u16 = 1 << 15;

// PCI Capability IDs
pub const PCI_CAP_PM: u8 = 0x01;       // Power Management
pub const PCI_CAP_AGP: u8 = 0x02;
pub const PCI_CAP_VPD: u8 = 0x03;      // Vital Product Data
pub const PCI_CAP_SLOT_ID: u8 = 0x04;
pub const PCI_CAP_MSI: u8 = 0x05;
pub const PCI_CAP_HOT_SWAP: u8 = 0x06;
pub const PCI_CAP_PCIX: u8 = 0x07;
pub const PCI_CAP_HT: u8 = 0x08;       // HyperTransport
pub const PCI_CAP_VENDOR: u8 = 0x09;
pub const PCI_CAP_DEBUG: u8 = 0x0A;
pub const PCI_CAP_CPCI_RS: u8 = 0x0B;
pub const PCI_CAP_HOT_PLUG: u8 = 0x0C;
pub const PCI_CAP_SUBSYS_VENDOR: u8 = 0x0D;
pub const PCI_CAP_AGP8X: u8 = 0x0E;
pub const PCI_CAP_SECURE: u8 = 0x0F;
pub const PCI_CAP_PCIE: u8 = 0x10;
pub const PCI_CAP_MSIX: u8 = 0x11;
pub const PCI_CAP_SATA: u8 = 0x12;
pub const PCI_CAP_AF: u8 = 0x13;       // Advanced Features

// PCIe Extended Capability IDs
pub const PCIE_EXT_CAP_AER: u16 = 0x0001;
pub const PCIE_EXT_CAP_VC: u16 = 0x0002;
pub const PCIE_EXT_CAP_SN: u16 = 0x0003;   // Serial Number
pub const PCIE_EXT_CAP_PWR: u16 = 0x0004;  // Power Budgeting
pub const PCIE_EXT_CAP_RCLD: u16 = 0x0005;
pub const PCIE_EXT_CAP_RCILC: u16 = 0x0006;
pub const PCIE_EXT_CAP_RCIEP: u16 = 0x0007;
pub const PCIE_EXT_CAP_MFVC: u16 = 0x0008;
pub const PCIE_EXT_CAP_VC2: u16 = 0x0009;
pub const PCIE_EXT_CAP_RCRB: u16 = 0x000A;
pub const PCIE_EXT_CAP_VENDOR: u16 = 0x000B;
pub const PCIE_EXT_CAP_ACS: u16 = 0x000D;
pub const PCIE_EXT_CAP_ARI: u16 = 0x000E;
pub const PCIE_EXT_CAP_ATS: u16 = 0x000F;
pub const PCIE_EXT_CAP_SRIOV: u16 = 0x0010;
pub const PCIE_EXT_CAP_MRIOV: u16 = 0x0011;
pub const PCIE_EXT_CAP_MULTICAST: u16 = 0x0012;
pub const PCIE_EXT_CAP_PRI: u16 = 0x0013;
pub const PCIE_EXT_CAP_RESIZE_BAR: u16 = 0x0015;
pub const PCIE_EXT_CAP_DPA: u16 = 0x0016;
pub const PCIE_EXT_CAP_TPH: u16 = 0x0017;
pub const PCIE_EXT_CAP_LTR: u16 = 0x0018;
pub const PCIE_EXT_CAP_SEC_PCIE: u16 = 0x0019;
pub const PCIE_EXT_CAP_PMUX: u16 = 0x001A;
pub const PCIE_EXT_CAP_PASID: u16 = 0x001B;
pub const PCIE_EXT_CAP_LNR: u16 = 0x001C;
pub const PCIE_EXT_CAP_DPC: u16 = 0x001D;
pub const PCIE_EXT_CAP_L1SS: u16 = 0x001E;
pub const PCIE_EXT_CAP_PTM: u16 = 0x001F;
pub const PCIE_EXT_CAP_DATA_LINK: u16 = 0x0025;
pub const PCIE_EXT_CAP_PHYSICAL: u16 = 0x0026;
pub const PCIE_EXT_CAP_DOE: u16 = 0x002E;
pub const PCIE_EXT_CAP_CXL: u16 = 0x0023;

// PCI Class codes
pub const PCI_CLASS_UNCLASSIFIED: u8 = 0x00;
pub const PCI_CLASS_STORAGE: u8 = 0x01;
pub const PCI_CLASS_NETWORK: u8 = 0x02;
pub const PCI_CLASS_DISPLAY: u8 = 0x03;
pub const PCI_CLASS_MULTIMEDIA: u8 = 0x04;
pub const PCI_CLASS_MEMORY: u8 = 0x05;
pub const PCI_CLASS_BRIDGE: u8 = 0x06;
pub const PCI_CLASS_COMM: u8 = 0x07;
pub const PCI_CLASS_SYSTEM: u8 = 0x08;
pub const PCI_CLASS_INPUT: u8 = 0x09;
pub const PCI_CLASS_DOCKING: u8 = 0x0A;
pub const PCI_CLASS_PROCESSOR: u8 = 0x0B;
pub const PCI_CLASS_SERIAL: u8 = 0x0C;
pub const PCI_CLASS_WIRELESS: u8 = 0x0D;
pub const PCI_CLASS_INTELLIGENT: u8 = 0x0E;
pub const PCI_CLASS_SATELLITE: u8 = 0x0F;
pub const PCI_CLASS_ENCRYPTION: u8 = 0x10;
pub const PCI_CLASS_SIGNAL: u8 = 0x11;
pub const PCI_CLASS_ACCELERATOR: u8 = 0x12;
pub const PCI_CLASS_NON_ESSENTIAL: u8 = 0x13;
pub const PCI_CLASS_COPROCESSOR: u8 = 0x40;

// ============================================================================
// PCI Device Structure
// ============================================================================

pub const BarType = enum {
    none,
    io,
    mem32,
    mem64,
};

pub const PciBar = struct {
    bar_type: BarType,
    base: u64,
    size: u64,
    prefetchable: bool,
    mapped_vaddr: u64,
};

pub const PciDevice = struct {
    // Location
    segment: u16,
    bus: u8,
    device: u5,
    function: u3,
    // Identity
    vendor_id: u16,
    device_id: u16,
    subsys_vendor_id: u16,
    subsys_device_id: u16,
    revision_id: u8,
    class_code: u8,
    subclass: u8,
    prog_if: u8,
    header_type: u8,
    // BARs
    bars: [6]PciBar,
    // Interrupt
    irq_line: u8,
    irq_pin: u8,
    msi_capable: bool,
    msix_capable: bool,
    msi_vector: u16,
    msix_table_bar: u8,
    msix_table_offset: u32,
    msix_pba_bar: u8,
    msix_pba_offset: u32,
    msix_table_size: u16,
    // PCIe
    pcie_cap_offset: u8,
    pcie_dev_type: PcieDeviceType,
    pcie_link_speed: PcieLinkSpeed,
    pcie_link_width: u8,
    pcie_max_speed: PcieLinkSpeed,
    pcie_max_width: u8,
    // Capabilities
    cap_offsets: [32]u8,
    num_caps: u8,
    ext_cap_offsets: [32]u16,
    num_ext_caps: u8,
    // Power management
    pm_cap_offset: u8,
    current_pm_state: u8,    // D0-D3
    pme_support: u8,
    // SR-IOV
    sriov_capable: bool,
    sriov_cap_offset: u16,
    sriov_total_vfs: u16,
    sriov_num_vfs: u16,
    is_virtual_function: bool,
    // AER
    aer_cap_offset: u16,
    // IOMMU group
    iommu_group: u16,
    // Driver binding
    driver_name: [32]u8,
    driver_bound: bool,
    // ECAM access
    ecam_base: u64,

    pub fn bdf(self: *const PciDevice) u16 {
        return (@as(u16, self.bus) << 8) | (@as(u16, self.device) << 3) | @as(u16, self.function);
    }

    pub fn config_read32(self: *const PciDevice, offset: u12) u32 {
        const addr = self.ecam_base + (@as(u64, self.bdf()) << 12) + offset;
        const ptr: *volatile u32 = @ptrFromInt(addr);
        return ptr.*;
    }

    pub fn config_write32(self: *const PciDevice, offset: u12, value: u32) void {
        const addr = self.ecam_base + (@as(u64, self.bdf()) << 12) + offset;
        const ptr: *volatile u32 = @ptrFromInt(addr);
        ptr.* = value;
    }

    pub fn config_read16(self: *const PciDevice, offset: u12) u16 {
        const addr = self.ecam_base + (@as(u64, self.bdf()) << 12) + offset;
        const ptr: *volatile u16 = @ptrFromInt(addr);
        return ptr.*;
    }

    pub fn config_write16(self: *const PciDevice, offset: u12, value: u16) void {
        const addr = self.ecam_base + (@as(u64, self.bdf()) << 12) + offset;
        const ptr: *volatile u16 = @ptrFromInt(addr);
        ptr.* = value;
    }

    pub fn config_read8(self: *const PciDevice, offset: u12) u8 {
        const addr = self.ecam_base + (@as(u64, self.bdf()) << 12) + offset;
        const ptr: *volatile u8 = @ptrFromInt(addr);
        return ptr.*;
    }

    /// Enable bus mastering
    pub fn enable_bus_master(self: *PciDevice) void {
        const cmd = self.config_read16(PCI_CFG_COMMAND);
        self.config_write16(PCI_CFG_COMMAND, cmd | PCI_CMD_BUS_MASTER | PCI_CMD_MEM_SPACE);
    }

    /// Disable legacy interrupts
    pub fn disable_legacy_int(self: *PciDevice) void {
        const cmd = self.config_read16(PCI_CFG_COMMAND);
        self.config_write16(PCI_CFG_COMMAND, cmd | PCI_CMD_INT_DISABLE);
    }
};

pub const PcieDeviceType = enum(u4) {
    endpoint = 0,
    legacy_endpoint = 1,
    root_port = 4,
    upstream_switch = 5,
    downstream_switch = 6,
    pcie_to_pci_bridge = 7,
    pci_to_pcie_bridge = 8,
    root_complex_integrated = 9,
    root_complex_event_collector = 10,
    unknown = 15,
};

pub const PcieLinkSpeed = enum(u8) {
    gen1_2_5gt = 1,    // 2.5 GT/s
    gen2_5gt = 2,      // 5.0 GT/s
    gen3_8gt = 3,      // 8.0 GT/s
    gen4_16gt = 4,     // 16.0 GT/s
    gen5_32gt = 5,     // 32.0 GT/s
    gen6_64gt = 6,     // 64.0 GT/s (PCIe 6.0)
    gen7_128gt = 7,    // 128.0 GT/s (PCIe 7.0)
    unknown = 0,
};

// ============================================================================
// MSI / MSI-X
// ============================================================================

pub const MsiCapability = struct {
    cap_offset: u8,
    message_control: u16,
    is_64bit: bool,
    per_vector_masking: bool,
    multi_message_capable: u3,  // log2 of max vectors
    multi_message_enable: u3,
    message_address: u64,
    message_data: u16,
    mask_bits: u32,
    pending_bits: u32,
};

pub const MsixEntry = struct {
    msg_addr_lo: u32,
    msg_addr_hi: u32,
    msg_data: u32,
    vector_control: u32,  // bit 0 = masked
};

pub const MsixCapability = struct {
    cap_offset: u8,
    table_size: u16,
    table_bar: u8,
    table_offset: u32,
    pba_bar: u8,
    pba_offset: u32,
    enabled: bool,
    function_mask: bool,
};

pub fn msi_compose_msg(vector: u8, cpu_id: u8, edge_trigger: bool, assert_: bool) struct { addr: u64, data: u32 } {
    // x86_64 MSI address format
    const addr: u64 = 0xFEE00000 | (@as(u64, cpu_id) << 12);
    var data: u32 = @as(u32, vector);
    if (!edge_trigger) data |= (1 << 15); // Level
    if (assert_) data |= (1 << 14); // Assert
    return .{ .addr = addr, .data = data };
}

// ============================================================================
// SR-IOV (Single Root I/O Virtualization)
// ============================================================================

pub const SriovCapability = struct {
    cap_offset: u16,
    capabilities: u32,
    control: u16,
    status: u16,
    initial_vfs: u16,
    total_vfs: u16,
    num_vfs: u16,
    function_dependency_link: u8,
    first_vf_offset: u16,
    vf_stride: u16,
    vf_device_id: u16,
    supported_page_sizes: u32,
    system_page_size: u32,
    vf_bars: [6]PciBar,
    vf_migration_state_offset: u32,
    vf_migration_state_bir: u8,
    ari_capable: bool,
};

/// Calculate VF routing ID
pub fn sriov_vf_rid(pf_bus: u8, pf_devfn: u8, first_vf_offset: u16, vf_stride: u16, vf_index: u16) u16 {
    const pf_rid = (@as(u16, pf_bus) << 8) | @as(u16, pf_devfn);
    return pf_rid + first_vf_offset + vf_index * vf_stride;
}

// ============================================================================
// AER (Advanced Error Reporting)
// ============================================================================

pub const AerCapability = struct {
    cap_offset: u16,
    // Uncorrectable error status
    unc_status: u32,
    unc_mask: u32,
    unc_severity: u32,
    // Correctable error status
    cor_status: u32,
    cor_mask: u32,
    // Advanced error control
    advanced_capabilities: u32,
    // Header log
    header_log: [4]u32,
    // Root error
    root_command: u32,
    root_status: u32,
    error_source_id: u32,
    // TLP prefix log
    tlp_prefix_log: [4]u32,
};

// Uncorrectable errors
pub const AER_UNC_DLP: u32 = 1 << 4;       // Data Link Protocol Error
pub const AER_UNC_SDES: u32 = 1 << 5;      // Surprise Down Error
pub const AER_UNC_POISON_TLP: u32 = 1 << 12; // Poisoned TLP
pub const AER_UNC_FCP: u32 = 1 << 13;      // Flow Control Protocol Error
pub const AER_UNC_COMP_TIMEOUT: u32 = 1 << 14; // Completion Timeout
pub const AER_UNC_COMP_ABORT: u32 = 1 << 15; // Completer Abort
pub const AER_UNC_UNEXP_COMP: u32 = 1 << 16; // Unexpected Completion
pub const AER_UNC_RX_OVERFLOW: u32 = 1 << 17; // Receiver Overflow
pub const AER_UNC_MALF_TLP: u32 = 1 << 18;  // Malformed TLP
pub const AER_UNC_ECRC: u32 = 1 << 19;      // ECRC Error
pub const AER_UNC_UNSUP_REQ: u32 = 1 << 20; // Unsupported Request
pub const AER_UNC_ACS_VIOL: u32 = 1 << 21;  // ACS Violation
pub const AER_UNC_INTERNAL: u32 = 1 << 22;  // Uncorrectable Internal Error
pub const AER_UNC_MC_BLOCKED: u32 = 1 << 23; // MC Blocked TLP
pub const AER_UNC_ATOMICOP_BLOCK: u32 = 1 << 24; // AtomicOp Egress Blocked
pub const AER_UNC_TLP_PREFIX: u32 = 1 << 25; // TLP Prefix Blocked

// Correctable errors
pub const AER_COR_RX_ERR: u32 = 1 << 0;     // Receiver Error
pub const AER_COR_BAD_TLP: u32 = 1 << 6;    // Bad TLP
pub const AER_COR_BAD_DLLP: u32 = 1 << 7;   // Bad DLLP
pub const AER_COR_REPLAY_NUM: u32 = 1 << 8;  // Replay Num Rollover
pub const AER_COR_REPLAY_TIMER: u32 = 1 << 12; // Replay Timer Timeout
pub const AER_COR_ADVISORY: u32 = 1 << 13;   // Advisory Non-Fatal Error
pub const AER_COR_INTERNAL: u32 = 1 << 14;   // Corrected Internal Error
pub const AER_COR_LOG_OVERFLOW: u32 = 1 << 15; // Header Log Overflow

// ============================================================================
// ASPM (Active State Power Management)
// ============================================================================

pub const AspmPolicy = enum(u8) {
    disabled = 0,
    l0s_only = 1,
    l1_only = 2,
    l0s_l1 = 3,
};

pub const AspmState = struct {
    policy: AspmPolicy,
    l0s_enabled: bool,
    l1_enabled: bool,
    l1_1_enabled: bool,  // L1.1 (PCI-PM L1)
    l1_2_enabled: bool,  // L1.2 (ASPM+PCI-PM L1)
    clkpm_enabled: bool,  // Clock PM
    l0s_acceptable_latency: u32,  // ns
    l1_acceptable_latency: u32,   // ns
    common_clock: bool,
};

// ============================================================================
// ACS (Access Control Services)
// ============================================================================

pub const AcsCapability = struct {
    cap_offset: u16,
    sv: bool,     // Source Validation
    tb: bool,     // Translation Blocking
    rr: bool,     // P2P Request Redirect
    cr: bool,     // P2P Completion Redirect
    uf: bool,     // Upstream Forwarding
    ec: bool,     // P2P Egress Control
    dt: bool,     // Direct Translated P2P
    enabled_mask: u16,
};

// ============================================================================
// DPC (Downstream Port Containment)
// ============================================================================

pub const DpcCapability = struct {
    cap_offset: u16,
    trigger_status: bool,
    trigger_reason: DpcTriggerReason,
    rp_pio_status: u32,
    rp_pio_mask: u32,
    rp_pio_severity: u32,
    sw_trigger: bool,
    rp_extensions: bool,
    poisoned_tlp_egress_blocking: bool,
};

pub const DpcTriggerReason = enum(u2) {
    unmasked_unc_error = 0,
    err_nonfatal = 1,
    err_fatal = 2,
    rp_pio_error = 3,
};

// ============================================================================
// PCIe Hotplug
// ============================================================================

pub const HotplugSlot = struct {
    slot_number: u16,
    bus: u8,
    device: u5,
    function: u3,
    // Capabilities
    attention_button: bool,
    power_controller: bool,
    mrl_sensor: bool,
    attention_indicator: bool,
    power_indicator: bool,
    hot_plug_surprise: bool,
    hot_plug_capable: bool,
    electromechanical_interlock: bool,
    no_command_completed: bool,
    // State
    occupied: bool,
    powered: bool,
    adapter_status: HotplugAdapterState,
    attention_led: LedState,
    power_led: LedState,
    power_fault: bool,
    mrl_closed: bool,
    presence_change_pending: bool,
};

pub const HotplugAdapterState = enum(u8) {
    empty,
    present,
    powered,
    enabled,
    failed,
};

pub const LedState = enum(u2) {
    off = 0,
    on = 1,
    blink = 2,
    na = 3,
};

// ============================================================================
// PCI Bus Enumeration
// ============================================================================

pub const MAX_PCI_BUSES = 256;
pub const MAX_PCI_DEVICES_PER_BUS = 32;
pub const MAX_PCI_FUNCTIONS = 8;
pub const MAX_PCI_TOTAL = 4096;

pub const PciBus = struct {
    number: u8,
    segment: u16,
    parent_bus: u8,
    is_root: bool,
    bridge_device: ?*PciDevice,
    devices: [MAX_PCI_DEVICES_PER_BUS * MAX_PCI_FUNCTIONS]?*PciDevice,
    device_count: u16,
    // Resource windows
    io_base: u32,
    io_limit: u32,
    mem_base: u64,
    mem_limit: u64,
    prefetch_base: u64,
    prefetch_limit: u64,
    subordinate_bus: u8,
};

pub const PciSubsystem = struct {
    // ECAM (Enhanced Configuration Access Mechanism)
    ecam_base: u64,
    ecam_segment: u16,
    ecam_start_bus: u8,
    ecam_end_bus: u8,
    // Buses
    buses: [MAX_PCI_BUSES]?PciBus,
    // All devices
    all_devices: [MAX_PCI_TOTAL]PciDevice,
    device_count: u16,
    // Legacy I/O port access
    legacy_io_enabled: bool,

    pub fn legacy_config_addr(bus: u8, device: u5, function: u3, offset: u8) u32 {
        return (1 << 31) | // Enable
            (@as(u32, bus) << 16) |
            (@as(u32, device) << 11) |
            (@as(u32, function) << 8) |
            (@as(u32, offset) & 0xFC);
    }

    /// Enumerate all PCI devices using ECAM
    pub fn enumerate(self: *PciSubsystem) void {
        var bus: u16 = self.ecam_start_bus;
        while (bus <= self.ecam_end_bus) : (bus += 1) {
            var dev: u8 = 0;
            while (dev < 32) : (dev += 1) {
                var func: u8 = 0;
                while (func < 8) : (func += 1) {
                    const ecam_offset = (@as(u64, bus) << 20) | (@as(u64, dev) << 15) | (@as(u64, func) << 12);
                    const cfg_base = self.ecam_base + ecam_offset;
                    const vendor_ptr: *volatile u16 = @ptrFromInt(cfg_base);
                    const vendor_id = vendor_ptr.*;

                    if (vendor_id == 0xFFFF) {
                        if (func == 0) break; // No device here
                        continue;
                    }

                    if (self.device_count >= MAX_PCI_TOTAL) return;

                    var pci_dev = &self.all_devices[self.device_count];
                    pci_dev.segment = self.ecam_segment;
                    pci_dev.bus = @truncate(bus);
                    pci_dev.device = @truncate(dev);
                    pci_dev.function = @truncate(func);
                    pci_dev.ecam_base = self.ecam_base;
                    pci_dev.vendor_id = vendor_id;
                    pci_dev.device_id = pci_dev.config_read16(PCI_CFG_DEVICE_ID);
                    pci_dev.class_code = pci_dev.config_read8(@as(u12, PCI_CFG_CLASS));
                    pci_dev.subclass = pci_dev.config_read8(@as(u12, PCI_CFG_SUBCLASS));
                    pci_dev.prog_if = pci_dev.config_read8(@as(u12, PCI_CFG_PROG_IF));
                    pci_dev.revision_id = pci_dev.config_read8(@as(u12, PCI_CFG_REV_ID));
                    pci_dev.header_type = pci_dev.config_read8(@as(u12, PCI_CFG_HEADER_TYPE));
                    pci_dev.irq_line = pci_dev.config_read8(@as(u12, PCI_CFG_INT_LINE));
                    pci_dev.irq_pin = pci_dev.config_read8(@as(u12, PCI_CFG_INT_PIN));

                    // Parse BARs
                    if (pci_dev.header_type & 0x7F == 0) {
                        self.parse_bars(pci_dev);
                    }

                    // Walk capability list
                    if (pci_dev.config_read16(PCI_CFG_STATUS) & PCI_STS_CAP_LIST != 0) {
                        self.walk_capabilities(pci_dev);
                    }

                    self.device_count += 1;

                    // Only scan other functions if multi-function
                    if (func == 0 and (pci_dev.header_type & 0x80 == 0)) break;
                }
            }
        }
    }

    fn parse_bars(self: *PciSubsystem, dev: *PciDevice) void {
        _ = self;
        var i: u8 = 0;
        while (i < 6) : (i += 1) {
            const bar_offset = @as(u12, PCI_CFG_BAR0) + @as(u12, i) * 4;
            const bar_val = dev.config_read32(bar_offset);

            if (bar_val == 0) {
                dev.bars[i] = PciBar{ .bar_type = .none, .base = 0, .size = 0, .prefetchable = false, .mapped_vaddr = 0 };
                continue;
            }

            if (bar_val & 1 != 0) {
                // I/O BAR
                dev.bars[i] = PciBar{
                    .bar_type = .io,
                    .base = bar_val & 0xFFFC,
                    .size = 0, // Need sizing
                    .prefetchable = false,
                    .mapped_vaddr = 0,
                };
            } else {
                const bar_type_bits = (bar_val >> 1) & 3;
                const prefetchable = (bar_val & 8) != 0;

                if (bar_type_bits == 2) {
                    // 64-bit BAR
                    if (i < 5) {
                        const bar_hi = dev.config_read32(bar_offset + 4);
                        dev.bars[i] = PciBar{
                            .bar_type = .mem64,
                            .base = (@as(u64, bar_hi) << 32) | (bar_val & 0xFFFFFFF0),
                            .size = 0,
                            .prefetchable = prefetchable,
                            .mapped_vaddr = 0,
                        };
                        dev.bars[i + 1] = PciBar{ .bar_type = .none, .base = 0, .size = 0, .prefetchable = false, .mapped_vaddr = 0 };
                        i += 1; // Skip next BAR (upper 32 bits)
                    }
                } else {
                    // 32-bit BAR
                    dev.bars[i] = PciBar{
                        .bar_type = .mem32,
                        .base = bar_val & 0xFFFFFFF0,
                        .size = 0,
                        .prefetchable = prefetchable,
                        .mapped_vaddr = 0,
                    };
                }
            }
        }
    }

    fn walk_capabilities(self: *PciSubsystem, dev: *PciDevice) void {
        _ = self;
        var ptr = dev.config_read8(@as(u12, PCI_CFG_CAP_PTR)) & 0xFC;
        var count: u8 = 0;

        while (ptr != 0 and count < 32) {
            const cap_id = dev.config_read8(@as(u12, ptr));
            dev.cap_offsets[count] = ptr;
            count += 1;

            switch (cap_id) {
                PCI_CAP_MSI => dev.msi_capable = true,
                PCI_CAP_MSIX => {
                    dev.msix_capable = true;
                    const msg_ctrl = dev.config_read16(@as(u12, ptr + 2));
                    dev.msix_table_size = (msg_ctrl & 0x7FF) + 1;
                    const table_reg = dev.config_read32(@as(u12, ptr + 4));
                    dev.msix_table_bar = @truncate(table_reg & 7);
                    dev.msix_table_offset = table_reg & 0xFFFFFFF8;
                    const pba_reg = dev.config_read32(@as(u12, ptr + 8));
                    dev.msix_pba_bar = @truncate(pba_reg & 7);
                    dev.msix_pba_offset = pba_reg & 0xFFFFFFF8;
                },
                PCI_CAP_PCIE => {
                    dev.pcie_cap_offset = ptr;
                    const pcie_caps = dev.config_read16(@as(u12, ptr + 2));
                    dev.pcie_dev_type = @enumFromInt(@as(u4, @truncate((pcie_caps >> 4) & 0xF)));
                    const link_status = dev.config_read16(@as(u12, ptr + 18));
                    dev.pcie_link_speed = @enumFromInt(@as(u8, @truncate(link_status & 0xF)));
                    dev.pcie_link_width = @truncate((link_status >> 4) & 0x3F);
                },
                PCI_CAP_PM => dev.pm_cap_offset = ptr,
                else => {},
            }

            ptr = dev.config_read8(@as(u12, ptr + 1)) & 0xFC;
        }
        dev.num_caps = count;
    }

    /// Find a device by vendor/device ID
    pub fn find_device(self: *PciSubsystem, vendor_id: u16, device_id: u16) ?*PciDevice {
        for (self.all_devices[0..self.device_count]) |*dev| {
            if (dev.vendor_id == vendor_id and dev.device_id == device_id) return dev;
        }
        return null;
    }

    /// Find devices by class code
    pub fn find_by_class(self: *PciSubsystem, class_code: u8, subclass: u8) [32]?*PciDevice {
        var result = [_]?*PciDevice{null} ** 32;
        var count: u8 = 0;
        for (self.all_devices[0..self.device_count]) |*dev| {
            if (dev.class_code == class_code and dev.subclass == subclass and count < 32) {
                result[count] = dev;
                count += 1;
            }
        }
        return result;
    }
};

// ============================================================================
// Vendor IDs (common)
// ============================================================================

pub const PCI_VENDOR_INTEL: u16 = 0x8086;
pub const PCI_VENDOR_AMD: u16 = 0x1022;
pub const PCI_VENDOR_NVIDIA: u16 = 0x10DE;
pub const PCI_VENDOR_QUALCOMM: u16 = 0x17CB;
pub const PCI_VENDOR_BROADCOM: u16 = 0x14E4;
pub const PCI_VENDOR_REALTEK: u16 = 0x10EC;
pub const PCI_VENDOR_SAMSUNG: u16 = 0x144D;
pub const PCI_VENDOR_TEXAS_INSTRUMENTS: u16 = 0x104C;
pub const PCI_VENDOR_MARVELL: u16 = 0x1B4B;
pub const PCI_VENDOR_MELLANOX: u16 = 0x15B3;
pub const PCI_VENDOR_QLOGIC: u16 = 0x1077;
pub const PCI_VENDOR_RED_HAT: u16 = 0x1AF4;  // VirtIO
pub const PCI_VENDOR_VMWARE: u16 = 0x15AD;
pub const PCI_VENDOR_MICROSOFT: u16 = 0x1414; // Hyper-V
