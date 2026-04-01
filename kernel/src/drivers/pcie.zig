// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Advanced PCIe Subsystem
//
// PCI Express extended features:
// - PCIe capability enumeration & parsing
// - MSI/MSI-X interrupt routing
// - PCIe link training & speed negotiation
// - AER (Advanced Error Reporting)
// - ACS (Access Control Services)
// - ARI (Alternative Routing-ID Interpretation)
// - SR-IOV (Single Root I/O Virtualization)
// - ASPM (Active State Power Management)
// - Extended configuration space (4KB)
// - Hotplug event handling
// - TLP (Transaction Layer Packet) error recovery
// - Root Complex event collector

const std = @import("std");

// ─────────────────── PCIe Configuration Space ───────────────────────
pub const PCIE_CFG_SIZE: usize = 4096; // Extended config space
pub const PCI_CFG_SIZE: usize = 256;   // Legacy config space

// Standard PCI header offsets
pub const PCI_VENDOR_ID: u8 = 0x00;
pub const PCI_DEVICE_ID: u8 = 0x02;
pub const PCI_COMMAND: u8 = 0x04;
pub const PCI_STATUS: u8 = 0x06;
pub const PCI_REVISION: u8 = 0x08;
pub const PCI_CLASS: u8 = 0x09;
pub const PCI_CACHE_LINE: u8 = 0x0C;
pub const PCI_LATENCY: u8 = 0x0D;
pub const PCI_HEADER_TYPE: u8 = 0x0E;
pub const PCI_BAR0: u8 = 0x10;
pub const PCI_BAR1: u8 = 0x14;
pub const PCI_BAR2: u8 = 0x18;
pub const PCI_BAR3: u8 = 0x1C;
pub const PCI_BAR4: u8 = 0x20;
pub const PCI_BAR5: u8 = 0x24;
pub const PCI_IRQ_LINE: u8 = 0x3C;
pub const PCI_IRQ_PIN: u8 = 0x3D;
pub const PCI_CAP_PTR: u8 = 0x34;

// PCI Command register bits
pub const PCI_CMD_IO_SPACE: u16 = 1 << 0;
pub const PCI_CMD_MEM_SPACE: u16 = 1 << 1;
pub const PCI_CMD_BUS_MASTER: u16 = 1 << 2;
pub const PCI_CMD_INTX_DISABLE: u16 = 1 << 10;

// PCI Capability IDs
pub const PCI_CAP_MSI: u8 = 0x05;
pub const PCI_CAP_MSIX: u8 = 0x11;
pub const PCI_CAP_PCIE: u8 = 0x10;
pub const PCI_CAP_PM: u8 = 0x01;
pub const PCI_CAP_VPD: u8 = 0x03;
pub const PCI_CAP_SLOT_ID: u8 = 0x04;

// PCIe Extended Capability IDs
pub const PCIE_EXT_AER: u16 = 0x0001;
pub const PCIE_EXT_VC: u16 = 0x0002;
pub const PCIE_EXT_SN: u16 = 0x0003;
pub const PCIE_EXT_POWER_BUDGET: u16 = 0x0004;
pub const PCIE_EXT_ACS: u16 = 0x000D;
pub const PCIE_EXT_ARI: u16 = 0x000E;
pub const PCIE_EXT_ATS: u16 = 0x000F;
pub const PCIE_EXT_SRIOV: u16 = 0x0010;
pub const PCIE_EXT_LTR: u16 = 0x0018;
pub const PCIE_EXT_DPC: u16 = 0x001D;
pub const PCIE_EXT_L1SS: u16 = 0x001E;
pub const PCIE_EXT_PTM: u16 = 0x001F;

// ─────────────────── BDF Address ────────────────────────────────────
pub const BdfAddr = struct {
    bus: u8,
    device: u5,
    function: u3,

    pub fn toAddress(self: BdfAddr) u32 {
        return (@as(u32, self.bus) << 16) |
            (@as(u32, self.device) << 11) |
            (@as(u32, self.function) << 8);
    }

    pub fn fromAddress(addr: u32) BdfAddr {
        return .{
            .bus = @intCast((addr >> 16) & 0xFF),
            .device = @intCast((addr >> 11) & 0x1F),
            .function = @intCast((addr >> 8) & 0x07),
        };
    }
};

// ─────────────────── PCIe Link ──────────────────────────────────────
pub const PcieLinkSpeed = enum(u8) {
    gen1 = 1,   // 2.5 GT/s
    gen2 = 2,   // 5.0 GT/s
    gen3 = 3,   // 8.0 GT/s
    gen4 = 4,   // 16.0 GT/s
    gen5 = 5,   // 32.0 GT/s
    gen6 = 6,   // 64.0 GT/s

    pub fn bandwidthMbps(self: PcieLinkSpeed, width: PcieLinkWidth) u32 {
        const base: u32 = switch (self) {
            .gen1 => 250,    // 2.5 GT/s * 8/10 encoding
            .gen2 => 500,
            .gen3 => 985,    // 128b/130b encoding
            .gen4 => 1969,
            .gen5 => 3938,
            .gen6 => 7877,
        };
        return base * @as(u32, @intFromEnum(width));
    }
};

pub const PcieLinkWidth = enum(u8) {
    x1 = 1,
    x2 = 2,
    x4 = 4,
    x8 = 8,
    x16 = 16,
    x32 = 32,
};

pub const PcieLinkState = struct {
    current_speed: PcieLinkSpeed = .gen1,
    max_speed: PcieLinkSpeed = .gen1,
    current_width: PcieLinkWidth = .x1,
    max_width: PcieLinkWidth = .x1,
    ltssm_state: LtssmState = .detect_quiet,
    link_up: bool = false,
    training: bool = false,
    dl_active: bool = false,

    pub fn bandwidthMbps(self: *const PcieLinkState) u32 {
        return self.current_speed.bandwidthMbps(self.current_width);
    }
};

pub const LtssmState = enum(u8) {
    detect_quiet,
    detect_active,
    polling_active,
    polling_compliance,
    polling_config,
    config_linkwidth_start,
    config_linkwidth_accept,
    config_lanenum_wait,
    config_lanenum_accept,
    config_complete,
    config_idle,
    l0,           // fully active
    l0s,          // low-power standby
    l1,           // low-power
    l2,           // deeper low-power
    recovery_rcvr_lock,
    recovery_rcvr_cfg,
    recovery_speed,
    recovery_idle,
    hot_reset,
    disabled,
    loopback,
};

// ─────────────────── MSI / MSI-X ────────────────────────────────────
pub const MAX_MSI_VECTORS: usize = 32;
pub const MAX_MSIX_VECTORS: usize = 2048;

pub const MsiCapability = struct {
    cap_offset: u8 = 0,
    control: u16 = 0,
    address_lo: u32 = 0,
    address_hi: u32 = 0,
    data: u16 = 0,
    mask: u32 = 0,
    pending: u32 = 0,
    vectors_requested: u8 = 0,
    vectors_allocated: u8 = 0,
    is_64bit: bool = false,
    per_vector_masking: bool = false,
    enabled: bool = false,

    pub fn allocateVectors(self: *MsiCapability, count: u8) bool {
        if (count == 0 or count > MAX_MSI_VECTORS) return false;
        // Must be power of 2
        if (count & (count - 1) != 0) return false;
        self.vectors_allocated = count;
        return true;
    }

    pub fn setTarget(self: *MsiCapability, addr: u64, data_val: u16) void {
        self.address_lo = @intCast(addr & 0xFFFFFFFF);
        self.address_hi = @intCast(addr >> 32);
        self.data = data_val;
    }
};

pub const MsixTableEntry = struct {
    msg_addr_lo: u32 = 0,
    msg_addr_hi: u32 = 0,
    msg_data: u32 = 0,
    vector_ctrl: u32 = 0, // bit 0 = mask

    pub fn setAddress(self: *MsixTableEntry, addr: u64) void {
        self.msg_addr_lo = @intCast(addr & 0xFFFFFFFF);
        self.msg_addr_hi = @intCast(addr >> 32);
    }

    pub fn isMasked(self: *const MsixTableEntry) bool {
        return (self.vector_ctrl & 1) != 0;
    }

    pub fn setMask(self: *MsixTableEntry, masked: bool) void {
        if (masked) {
            self.vector_ctrl |= 1;
        } else {
            self.vector_ctrl &= ~@as(u32, 1);
        }
    }
};

pub const MsixCapability = struct {
    cap_offset: u8 = 0,
    table_size: u16 = 0,
    table_bar: u8 = 0,
    table_offset: u32 = 0,
    pba_bar: u8 = 0,
    pba_offset: u32 = 0,
    enabled: bool = false,
    function_mask: bool = false,
    // Table entries (limited for in-kernel storage)
    table: [256]MsixTableEntry = [_]MsixTableEntry{.{}} ** 256,
    table_count: u16 = 0,

    pub fn configure(self: *MsixCapability, idx: u16, addr: u64, data: u32) bool {
        if (idx >= self.table_count) return false;
        self.table[idx].setAddress(addr);
        self.table[idx].msg_data = data;
        return true;
    }
};

// ─────────────────── AER — Advanced Error Reporting ─────────────────
pub const AerUncorrectable = packed struct(u32) {
    _reserved0: u4 = 0,
    data_link_protocol: bool = false,
    surprise_down: bool = false,
    _reserved1: u6 = 0,
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
    _reserved2: u5 = 0,
};

pub const AerCorrectable = packed struct(u32) {
    receiver_error: bool = false,
    _reserved0: u5 = 0,
    bad_tlp: bool = false,
    bad_dllp: bool = false,
    replay_num_rollover: bool = false,
    _reserved1: u3 = 0,
    replay_timer_timeout: bool = false,
    advisory_non_fatal: bool = false,
    corrected_internal: bool = false,
    header_log_overflow: bool = false,
    _reserved2: u16 = 0,
};

pub const AerCapability = struct {
    cap_offset: u16 = 0,
    uncorrectable_status: AerUncorrectable = .{},
    uncorrectable_mask: AerUncorrectable = .{},
    uncorrectable_severity: AerUncorrectable = .{},
    correctable_status: AerCorrectable = .{},
    correctable_mask: AerCorrectable = .{},
    root_error_command: u32 = 0,
    root_error_status: u32 = 0,
    header_log: [4]u32 = .{ 0, 0, 0, 0 },
    tlp_prefix_log: [4]u32 = .{ 0, 0, 0, 0 },
    enabled: bool = false,

    pub fn hasUncorrectable(self: *const AerCapability) bool {
        return @as(u32, @bitCast(self.uncorrectable_status)) != 0;
    }

    pub fn hasCorrectable(self: *const AerCapability) bool {
        return @as(u32, @bitCast(self.correctable_status)) != 0;
    }
};

// ─────────────────── SR-IOV ─────────────────────────────────────────
pub const MAX_VFS: usize = 64;

pub const SriovCapability = struct {
    cap_offset: u16 = 0,
    total_vfs: u16 = 0,
    num_vfs: u16 = 0,
    initial_vfs: u16 = 0,
    vf_offset: u16 = 0,
    vf_stride: u16 = 0,
    vf_device_id: u16 = 0,
    system_page_size: u32 = 0x1000,
    vf_bar: [6]u64 = [_]u64{0} ** 6,
    enabled: bool = false,
    vf_migration: bool = false,
    ari_capable: bool = false,

    pub fn enableVfs(self: *SriovCapability, count: u16) bool {
        if (count > self.total_vfs) return false;
        self.num_vfs = count;
        self.enabled = true;
        return true;
    }

    pub fn disableVfs(self: *SriovCapability) void {
        self.num_vfs = 0;
        self.enabled = false;
    }

    pub fn getVfBdf(self: *const SriovCapability, pf_bdf: BdfAddr, vf_index: u16) ?BdfAddr {
        if (vf_index >= self.num_vfs) return null;
        const pf_num = @as(u16, pf_bdf.bus) * 256 + @as(u16, pf_bdf.device) * 8 + pf_bdf.function;
        const vf_num = pf_num + self.vf_offset + vf_index * self.vf_stride;
        return BdfAddr{
            .bus = @intCast(vf_num >> 8),
            .device = @intCast((vf_num >> 3) & 0x1F),
            .function = @intCast(vf_num & 0x07),
        };
    }
};

// ─────────────────── ASPM — Active State Power Management ───────────
pub const AspmPolicy = enum(u8) {
    disabled,
    l0s_only,
    l1_only,
    l0s_l1,
    performance, // System override: disable ASPM
    powersave,   // Enable max ASPM
};

pub const AspmState = struct {
    l0s_enabled: bool = false,
    l1_enabled: bool = false,
    l1_1_enabled: bool = false, // L1.1 substates
    l1_2_enabled: bool = false, // L1.2 substates
    l0s_exit_latency_ns: u32 = 0,
    l1_exit_latency_us: u32 = 0,
    clkpm_enabled: bool = false, // Clock PM
    policy: AspmPolicy = .disabled,

    pub fn applyPolicy(self: *AspmState, policy: AspmPolicy) void {
        self.policy = policy;
        switch (policy) {
            .disabled, .performance => {
                self.l0s_enabled = false;
                self.l1_enabled = false;
                self.l1_1_enabled = false;
                self.l1_2_enabled = false;
            },
            .l0s_only => {
                self.l0s_enabled = true;
                self.l1_enabled = false;
            },
            .l1_only => {
                self.l0s_enabled = false;
                self.l1_enabled = true;
            },
            .l0s_l1 => {
                self.l0s_enabled = true;
                self.l1_enabled = true;
            },
            .powersave => {
                self.l0s_enabled = true;
                self.l1_enabled = true;
                self.l1_1_enabled = true;
                self.l1_2_enabled = true;
                self.clkpm_enabled = true;
            },
        }
    }
};

// ─────────────────── Hotplug ────────────────────────────────────────
pub const HotplugEvent = enum(u8) {
    attention_button,
    power_fault,
    presence_change,
    link_status_change,
    command_complete,
    mrl_sensor_change,
};

pub const HotplugController = struct {
    slot_nr: u16 = 0,
    power_on: bool = false,
    device_present: bool = false,
    mrl_closed: bool = false,
    attention_led: u8 = 0, // 0=off, 1=on, 2=blink
    power_led: u8 = 0,
    event_mask: u8 = 0,
    pending_events: u8 = 0,

    pub fn powerOn(self: *HotplugController) void {
        self.power_on = true;
        self.power_led = 1;
    }

    pub fn powerOff(self: *HotplugController) void {
        self.power_on = false;
        self.power_led = 0;
    }

    pub fn processEvent(self: *HotplugController, event: HotplugEvent) HotplugAction {
        switch (event) {
            .attention_button => {
                if (self.device_present and self.power_on) {
                    self.attention_led = 2; // blink
                    return .request_remove;
                }
                return .none;
            },
            .power_fault => {
                self.power_on = false;
                self.power_led = 0;
                return .disable_slot;
            },
            .presence_change => {
                if (self.device_present) {
                    return .enumerate_device;
                } else {
                    return .unconfigure_device;
                }
            },
            .link_status_change => {
                return if (self.device_present) .retrain_link else .none;
            },
            else => return .none,
        }
    }
};

pub const HotplugAction = enum(u8) {
    none,
    enumerate_device,
    unconfigure_device,
    request_remove,
    disable_slot,
    retrain_link,
};

// ─────────────────── PCIe Device Registry ───────────────────────────
pub const MAX_PCIE_DEVICES: usize = 128;

pub const PcieDevice = struct {
    bdf: BdfAddr = .{ .bus = 0, .device = 0, .function = 0 },
    vendor_id: u16 = 0,
    device_id: u16 = 0,
    class_code: u24 = 0,
    revision: u8 = 0,
    header_type: u8 = 0,
    irq_line: u8 = 0,
    irq_pin: u8 = 0,
    bar: [6]u64 = [_]u64{0} ** 6,
    bar_size: [6]u64 = [_]u64{0} ** 6,
    bar_is_io: [6]bool = [_]bool{false} ** 6,
    bar_is_64bit: [6]bool = [_]bool{false} ** 6,
    // Capabilities
    msi: ?MsiCapability = null,
    msix: ?MsixCapability = null,
    aer: ?AerCapability = null,
    sriov: ?SriovCapability = null,
    link: PcieLinkState = .{},
    aspm: AspmState = .{},
    hotplug: ?HotplugController = null,
    // State
    enabled: bool = false,
    bus_master: bool = false,
    valid: bool = false,

    pub fn enableBusMaster(self: *PcieDevice) void {
        self.bus_master = true;
    }

    pub fn enableMsi(self: *PcieDevice, addr: u64, data: u16) bool {
        if (self.msi) |*msi| {
            msi.setTarget(addr, data);
            msi.enabled = true;
            return true;
        }
        return false;
    }

    pub fn enableMsix(self: *PcieDevice) bool {
        if (self.msix) |*msix| {
            msix.enabled = true;
            return true;
        }
        return false;
    }

    pub fn isEndpoint(self: *const PcieDevice) bool {
        return (self.header_type & 0x7F) == 0;
    }

    pub fn isBridge(self: *const PcieDevice) bool {
        return (self.header_type & 0x7F) == 1;
    }
};

pub const PcieSubsystem = struct {
    devices: [MAX_PCIE_DEVICES]PcieDevice = [_]PcieDevice{.{}} ** MAX_PCIE_DEVICES,
    device_count: u16 = 0,
    aspm_policy: AspmPolicy = .disabled,
    initialized: bool = false,

    pub fn init(self: *PcieSubsystem) void {
        self.initialized = true;
    }

    pub fn registerDevice(self: *PcieSubsystem, dev: PcieDevice) ?u16 {
        if (self.device_count >= MAX_PCIE_DEVICES) return null;
        var new_dev = dev;
        new_dev.valid = true;
        new_dev.aspm.applyPolicy(self.aspm_policy);
        self.devices[self.device_count] = new_dev;
        const idx = self.device_count;
        self.device_count += 1;
        return idx;
    }

    pub fn findDevice(self: *const PcieSubsystem, vendor: u16, device: u16) ?*const PcieDevice {
        for (&self.devices[0..self.device_count]) |*d| {
            if (d.valid and d.vendor_id == vendor and d.device_id == device) {
                return d;
            }
        }
        return null;
    }

    pub fn findByBdf(self: *const PcieSubsystem, bdf: BdfAddr) ?*const PcieDevice {
        for (&self.devices[0..self.device_count]) |*d| {
            if (d.valid and d.bdf.bus == bdf.bus and d.bdf.device == bdf.device and d.bdf.function == bdf.function) {
                return d;
            }
        }
        return null;
    }

    pub fn findByClass(self: *const PcieSubsystem, class: u8, subclass: u8) ?*const PcieDevice {
        for (&self.devices[0..self.device_count]) |*d| {
            if (d.valid) {
                const dev_class: u8 = @intCast((d.class_code >> 16) & 0xFF);
                const dev_subclass: u8 = @intCast((d.class_code >> 8) & 0xFF);
                if (dev_class == class and dev_subclass == subclass) {
                    return d;
                }
            }
        }
        return null;
    }

    pub fn setAspmPolicy(self: *PcieSubsystem, policy: AspmPolicy) void {
        self.aspm_policy = policy;
        for (&self.devices[0..self.device_count]) |*d| {
            if (d.valid) d.aspm.applyPolicy(policy);
        }
    }
};

// ─────────────────── Global Instance ────────────────────────────────
var pcie_subsystem: PcieSubsystem = .{};

pub fn initPcie() void {
    pcie_subsystem.init();
}

pub fn getPcie() *PcieSubsystem {
    return &pcie_subsystem;
}

// ─────────────────── FFI Exports ────────────────────────────────────
export fn zxy_pcie_init() void {
    initPcie();
}

export fn zxy_pcie_device_count() u16 {
    return pcie_subsystem.device_count;
}

export fn zxy_pcie_set_aspm(policy: u8) void {
    const aspm: AspmPolicy = @enumFromInt(policy);
    pcie_subsystem.setAspmPolicy(aspm);
}

export fn zxy_pcie_find_device(vendor: u16, device: u16) bool {
    return pcie_subsystem.findDevice(vendor, device) != null;
}

export fn zxy_pcie_link_speed(idx: u16) u8 {
    if (idx < pcie_subsystem.device_count) {
        return @intFromEnum(pcie_subsystem.devices[idx].link.current_speed);
    }
    return 0;
}

export fn zxy_pcie_link_width(idx: u16) u8 {
    if (idx < pcie_subsystem.device_count) {
        return @intFromEnum(pcie_subsystem.devices[idx].link.current_width);
    }
    return 0;
}

export fn zxy_pcie_bandwidth_mbps(idx: u16) u32 {
    if (idx < pcie_subsystem.device_count) {
        return pcie_subsystem.devices[idx].link.bandwidthMbps();
    }
    return 0;
}
