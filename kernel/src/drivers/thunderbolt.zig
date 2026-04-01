// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel - Thunderbolt/USB4 Controller Driver
// Supports Thunderbolt 3/4/5 and USB4 v2.0 tunneling, security, power delivery

const std = @import("std");

// ============================================================================
// Thunderbolt/USB4 Constants
// ============================================================================

pub const TB_MAX_CONTROLLERS: u32 = 8;
pub const TB_MAX_PORTS: u32 = 64;
pub const TB_MAX_TUNNELS: u32 = 128;
pub const TB_MAX_SWITCHES: u32 = 32;
pub const TB_MAX_ROUTES: u32 = 256;

pub const TB_RING_SIZE: u32 = 256;
pub const TB_DMA_CREDITS: u32 = 14;

// Thunderbolt generation
pub const TB_GEN_THUNDERBOLT3: u8 = 3;
pub const TB_GEN_THUNDERBOLT4: u8 = 4;
pub const TB_GEN_THUNDERBOLT5: u8 = 5;
pub const TB_GEN_USB4_V1: u8 = 10;
pub const TB_GEN_USB4_V2: u8 = 11;

// Link speed (Gb/s per lane)
pub const TB_LINK_SPEED_10: u32 = 10;
pub const TB_LINK_SPEED_20: u32 = 20;
pub const TB_LINK_SPEED_40: u32 = 40;
pub const TB_LINK_SPEED_80: u32 = 80;   // TB5 PAM-3
pub const TB_LINK_SPEED_120: u32 = 120;  // TB5 bidirectional

// Port types
pub const TB_PORT_INACTIVE: u8 = 0;
pub const TB_PORT_PCIE_DOWN: u8 = 1;
pub const TB_PORT_PCIE_UP: u8 = 2;
pub const TB_PORT_DP_HDMI_IN: u8 = 3;
pub const TB_PORT_DP_HDMI_OUT: u8 = 4;
pub const TB_PORT_USB3_DOWN: u8 = 5;
pub const TB_PORT_USB3_UP: u8 = 6;
pub const TB_PORT_NHI: u8 = 7;

// Adapter types
pub const TB_ADAPTER_LANE: u8 = 0;
pub const TB_ADAPTER_HOST: u8 = 1;
pub const TB_ADAPTER_PCIE: u8 = 2;
pub const TB_ADAPTER_DP: u8 = 3;
pub const TB_ADAPTER_USB3: u8 = 4;

// Security levels
pub const TB_SECURITY_NONE: u8 = 0;
pub const TB_SECURITY_USER: u8 = 1;
pub const TB_SECURITY_SECURE: u8 = 2;
pub const TB_SECURITY_DP_ONLY: u8 = 3;
pub const TB_SECURITY_USB_ONLY: u8 = 4;
pub const TB_SECURITY_NOPCIE: u8 = 5;

// ============================================================================
// NHI (Native Host Interface) Registers
// ============================================================================

pub const NHI_MMIO_SIZE: u64 = 0x40000;

pub const NHI_CAPS: u32 = 0x0;
pub const NHI_MAILBOX_CMD: u32 = 0x10;
pub const NHI_MAILBOX_DATA: u32 = 0x14;
pub const NHI_INTVEC: u32 = 0x20;
pub const NHI_FW_STS: u32 = 0x39944;

// Ring registers (per ring)
pub const RING_PHYS_ADDR_LO: u32 = 0x0;
pub const RING_PHYS_ADDR_HI: u32 = 0x4;
pub const RING_SIZE_FLAGS: u32 = 0x8;
pub const RING_HEAD: u32 = 0xC;
pub const RING_TAIL: u32 = 0x10;

// ============================================================================
// Thunderbolt Config Space
// ============================================================================

pub const TB_CFG_SPACE_ROUTER: u8 = 0;
pub const TB_CFG_SPACE_ADAPTER: u8 = 1;
pub const TB_CFG_SPACE_PATH: u8 = 2;
pub const TB_CFG_SPACE_COUNTER: u8 = 3;

// Router config offsets
pub const TB_CFG_VENDOR_ID: u32 = 0x0;
pub const TB_CFG_DEVICE_ID: u32 = 0x1;
pub const TB_CFG_REVID: u32 = 0x2;
pub const TB_CFG_ROUTE_HI: u32 = 0x3;
pub const TB_CFG_ROUTE_LO: u32 = 0x4;
pub const TB_CFG_MAX_ADAPTER: u32 = 0x5;
pub const TB_CFG_DEPTH: u32 = 0x6;
pub const TB_CFG_LINK_SPEED: u32 = 0x7;
pub const TB_CFG_UPSTREAM_PORT: u32 = 0x8;
pub const TB_CFG_CAPABILITY: u32 = 0x9;
pub const TB_CFG_SECURITY: u32 = 0xA;
pub const TB_CFG_GUID_LO: u32 = 0xC;
pub const TB_CFG_GUID_HI: u32 = 0xD;

// Capability IDs
pub const TB_CAP_VSC: u8 = 0x05;      // Vendor Specific
pub const TB_CAP_TMU: u8 = 0x03;      // Time Management Unit
pub const TB_CAP_IECS: u8 = 0x04;     // Inter-domain Event
pub const TB_CAP_LC: u8 = 0x06;       // Lane Adapter
pub const TB_CAP_USB4_PORT: u8 = 0x07;
pub const TB_CAP_PCIE: u8 = 0x08;
pub const TB_CAP_DP: u8 = 0x09;
pub const TB_CAP_USB3: u8 = 0x0A;

// ============================================================================
// Data Structures
// ============================================================================

pub const RingDescriptor = extern struct {
    addr_lo: u32,
    addr_hi: u32,
    length: u16,
    eof_sof: u8,
    flags: u8,
    request_id: u16,
    crc32: u16,
    timestamp: u32,

    pub fn set_address(self: *RingDescriptor, phys: u64) void {
        self.addr_lo = @truncate(phys);
        self.addr_hi = @truncate(phys >> 32);
    }

    pub fn get_address(self: *const RingDescriptor) u64 {
        return @as(u64, self.addr_hi) << 32 | @as(u64, self.addr_lo);
    }

    pub fn is_done(self: *const RingDescriptor) bool {
        return (self.flags & 0x80) != 0;
    }
};

pub const TbRing = struct {
    descriptors: [*]RingDescriptor,
    nr_descriptors: u32,
    head: u32,
    tail: u32,
    is_tx: bool,
    running: bool,
    hop: u8,
    // MMIO base for this ring
    mmio_base: u64,

    pub fn init(self: *TbRing) void {
        self.head = 0;
        self.tail = 0;
        self.running = false;
    }

    pub fn advance_head(self: *TbRing) void {
        self.head = (self.head + 1) % self.nr_descriptors;
    }

    pub fn advance_tail(self: *TbRing) void {
        self.tail = (self.tail + 1) % self.nr_descriptors;
    }

    pub fn is_empty(self: *const TbRing) bool {
        return self.head == self.tail;
    }

    pub fn is_full(self: *const TbRing) bool {
        return ((self.tail + 1) % self.nr_descriptors) == self.head;
    }

    pub fn available(self: *const TbRing) u32 {
        if self.tail >= self.head) {
            return self.tail - self.head;
        }
        return self.nr_descriptors - self.head + self.tail;
    }
};

pub const TbPort = struct {
    port_number: u8,
    port_type: u8,
    adapter_type: u8,
    generation: u8,
    enabled: bool,
    bonded: bool,        // Lane bonding
    link_speed: u32,     // Gbps
    link_width: u8,      // Number of lanes
    remote_port: ?*TbPort,
    switch_handle: u32,  // Parent switch
    // Capabilities
    has_pcie: bool,
    has_dp: bool,
    has_usb3: bool,
    has_tmu: bool,
    // Lane adapter state
    lane_active: bool,
    negotiated_speed: u32,
    // DisplayPort
    dp_cap_bw: u32,     // Max bandwidth Mbps
    dp_allocated_bw: u32,
    // USB 3
    usb3_max_speed: u32,
    // PCIe
    pcie_max_speed: u32,
    pcie_max_width: u8,
    // Config space offset
    config_offset: u32,

    pub fn is_upstream(self: *const TbPort) bool {
        return self.port_type == TB_PORT_PCIE_UP or
            self.port_type == TB_PORT_USB3_UP;
    }

    pub fn is_downstream(self: *const TbPort) bool {
        return self.port_type == TB_PORT_PCIE_DOWN or
            self.port_type == TB_PORT_USB3_DOWN;
    }

    pub fn max_bandwidth_gbps(self: *const TbPort) u32 {
        return self.link_speed * @as(u32, self.link_width);
    }
};

pub const TbSwitch = struct {
    route: u64,
    depth: u8,
    generation: u8,
    vendor_id: u16,
    device_id: u16,
    revision: u8,
    guid: [2]u64,
    security_level: u8,
    authorized: bool,
    key: [32]u8,         // Challenge-response key
    key_valid: bool,
    max_adapter: u8,
    ports: [TB_MAX_PORTS]?TbPort,
    nr_ports: u32,
    upstream_port: u8,
    // Power
    power_state: u8,     // 0=D0, 3=D3
    wakeup_enabled: bool,
    // TMU (Time Management Unit)
    tmu_mode: TmuMode,
    tmu_offset: i64,
    // USB4 specific
    usb4_version: u8,
    cm_support: bool,     // Connection Manager
    // Config space
    config: [256]u32,

    pub fn is_host_router(self: *const TbSwitch) bool {
        return self.depth == 0;
    }

    pub fn find_port(self: *TbSwitch, port_num: u8) ?*TbPort {
        for (&self.ports) |*maybe_port| {
            if (maybe_port.*) |*port| {
                if (port.port_number == port_num) return port;
            }
        }
        return null;
    }
};

pub const TmuMode = enum(u8) {
    off = 0,
    lowres = 1,     // Low resolution (us)
    hifi_unidirectional = 2,
    hifi_bidirectional = 3,
    enhanced = 4,    // USB4 v2
};

// ============================================================================
// Tunnel Management
// ============================================================================

pub const TunnelType = enum(u8) {
    pcie = 0,
    dp = 1,
    usb3 = 2,
    dma = 3,        // DMA tunneling (Thunderbolt networking)
    // Zxyphor extensions
    zxy_low_latency = 200,
    zxy_qos_guaranteed = 201,
};

pub const TbTunnel = struct {
    tunnel_type: TunnelType,
    src_port: u8,
    src_switch: u32, // Switch index
    dst_port: u8,
    dst_switch: u32,
    activated: bool,
    bandwidth_allocated: u32, // Mbps
    bandwidth_consumed: u32,
    // Path hops
    hops: [16]TbPathHop,
    nr_hops: u32,
    // QoS
    priority: u8,
    weight: u16,
    max_credits: u8,
    // Stats
    packets_tx: u64,
    packets_rx: u64,
    bytes_tx: u64,
    bytes_rx: u64,
    errors: u64,
};

pub const TbPathHop = struct {
    switch_index: u32,
    in_port: u8,
    in_hop: u8,
    out_port: u8,
    out_hop: u8,
    next_hop_index: u32,
    initial_credits: u8,
};

// ============================================================================
// DisplayPort Tunneling
// ============================================================================

pub const DpCapability = struct {
    max_bw: u32,          // Max bandwidth Mbps
    max_lanes: u8,
    max_rate: u32,        // Max link rate (Hz)
    dsc_support: bool,    // Display Stream Compression
    fec_support: bool,    // Forward Error Correction
    hdmi_support: bool,
    // USB4 DP BW management
    estimated_bw: u32,
    allocated_bw: u32,
    requested_bw: u32,
    granularity: u32,
};

pub const DpTunnel = struct {
    base: TbTunnel,
    dp_cap: DpCapability,
    // DP IN/OUT adapters
    dp_in_adapter: u8,
    dp_out_adapter: u8,
    // Active link
    link_rate: u32,
    lane_count: u8,
    bpp: u8,
    pixel_clock: u32,
    // LTTPR
    lttpr_count: u8,
    // BW allocation mode
    bw_alloc_mode: bool,
    bw_alloc_supported: bool,
};

// ============================================================================
// PCIe Tunneling
// ============================================================================

pub const PcieTunnel = struct {
    base: TbTunnel,
    // PCIe adapter info
    pcie_up_adapter: u8,
    pcie_down_adapter: u8,
    // Link info
    max_speed: u8,        // 1=2.5GT/s, 2=5, 3=8, 4=16, 5=32, 6=64
    max_width: u8,
    current_speed: u8,
    current_width: u8,
    // ACS
    acs_enabled: bool,
    // Hotplug
    hotplug_capable: bool,
    device_present: bool,
};

// ============================================================================
// USB3 Tunneling
// ============================================================================

pub const Usb3Tunnel = struct {
    base: TbTunnel,
    usb3_up_adapter: u8,
    usb3_down_adapter: u8,
    // Speed
    max_speed: u32,       // Mbps: 5000, 10000, 20000
    current_speed: u32,
    // BW
    allocated_up: u32,
    allocated_down: u32,
};

// ============================================================================
// DMA/Networking Tunnel
// ============================================================================

pub const DmaTunnel = struct {
    base: TbTunnel,
    // Rings
    tx_ring: u8,
    rx_ring: u8,
    // Path
    tx_hops: [8]TbPathHop,
    rx_hops: [8]TbPathHop,
    tx_nr_hops: u8,
    rx_nr_hops: u8,
    // Network
    local_uuid: [16]u8,
    remote_uuid: [16]u8,
    match_frame_id: u32,
};

// ============================================================================
// Bandwidth Management
// ============================================================================

pub const TbBandwidthGroup = struct {
    group_id: u8,
    tunnels: [16]u32,     // Tunnel indices
    nr_tunnels: u32,
    total_bandwidth: u32,  // Mbps
    reserved_bandwidth: u32,
    // Per-type allocation
    pcie_reserved: u32,
    dp_reserved: u32,
    usb3_reserved: u32,
    dma_reserved: u32,
};

// ============================================================================
// Power Management
// ============================================================================

pub const TbPowerState = enum(u8) {
    active = 0,         // D0
    idle = 1,           // Runtime idle
    suspended = 2,      // D3hot
    powered_off = 3,    // D3cold
    // USB4 CLx states
    cl0s = 4,           // CL0s (link low power)
    cl1 = 5,            // CL1
    cl2 = 6,            // CL2
};

pub const TbPowerManagement = struct {
    state: TbPowerState,
    clx_supported: u8,   // Bitmask of CL states
    clx_enabled: u8,
    // Runtime PM
    rpm_active: bool,
    rpm_suspended: bool,
    runtime_idle_ms: u32,
    autosuspend_delay_ms: u32,
    // Link power
    link_power_down: bool,
    wake_supported: bool,
    wake_enabled: bool,
    // Stats
    active_time_ms: u64,
    suspended_time_ms: u64,
    transitions: u64,
};

// ============================================================================
// Security & Authorization
// ============================================================================

pub const TbSecurityLevel = enum(u8) {
    none = 0,
    user = 1,        // User must approve
    secure = 2,      // Challenge-response
    dp_only = 3,     // Only DP tunnels allowed
    usb_only = 4,    // Only USB tunnels allowed
    no_pcie = 5,     // Everything except PCIe
    // Zxyphor
    zxy_verified = 200, // Only verified device firmware
};

pub const TbAuthorization = struct {
    level: TbSecurityLevel,
    approved_devices: [64]TbDeviceAuth,
    nr_approved: u32,
    denied_devices: [64]TbDeviceAuth,
    nr_denied: u32,
    // Challenge-response
    host_key: [32]u8,
    host_key_valid: bool,
};

pub const TbDeviceAuth = struct {
    uuid: [16]u8,
    key: [32]u8,
    authorized: bool,
    timestamp: u64,
    user_approved: bool,
};

// ============================================================================
// ICM (Internal Connection Manager) / Software CM
// ============================================================================

pub const CmType = enum(u8) {
    icm = 0,         // Firmware CM (Intel)
    software = 1,    // Software CM (USB4)
};

pub const IcmMessage = extern struct {
    code: u8,
    flags: u8,
    packet_id: u8,
    total_packets: u8,
    data: [252]u8,
};

pub const IcmEvent = enum(u8) {
    device_connected = 0,
    device_disconnected = 1,
    dp_bandwidth_notification = 2,
    domain_connected = 3,
    domain_disconnected = 4,
    rtd3_veto = 5,
    // USB4
    usb4_router_added = 10,
    usb4_router_removed = 11,
    usb4_dp_bw_request = 12,
};

// ============================================================================
// USB4 Router Operations
// ============================================================================

pub const Usb4RouterOp = enum(u8) {
    read_route = 0,
    write_route = 1,
    read_adapter = 2,
    write_adapter = 3,
    reset = 4,
    read_uuid = 5,
    read_link_status = 6,
    alloc_bw = 7,
    dealloc_bw = 8,
    nvm_authenticate = 9,
    nvm_read = 10,
    nvm_write = 11,
    nvm_set_offset = 12,
    connection_manager = 13,
    // USB4 v2
    margin = 14,
    receiver_info = 15,
};

// ============================================================================
// NVM (Non-Volatile Memory) / Firmware Update
// ============================================================================

pub const TbNvm = struct {
    is_active: bool,
    authenticating: bool,
    flushed: bool,
    // Active NVM info
    active_major: u16,
    active_minor: u16,
    active_css: u32,
    // Non-active NVM (staging area)
    buf: [*]u8,
    buf_size: u32,
    written: u32,
    // Authentication status
    auth_status: NvmAuthStatus,
};

pub const NvmAuthStatus = enum(u8) {
    none = 0,
    in_progress = 1,
    success = 2,
    failure_crc = 3,
    failure_auth = 4,
    failure_internal = 5,
    failure_timeout = 6,
};

// ============================================================================
// Thunderbolt Controller (Top-Level)
// ============================================================================

pub const TbController = struct {
    // Identity
    controller_id: u32,
    generation: u8,
    vendor_id: u16,
    device_id: u16,
    // MMIO
    mmio_base: u64,
    mmio_size: u64,
    // Rings
    tx_rings: [32]TbRing,
    rx_rings: [32]TbRing,
    nr_tx_rings: u32,
    nr_rx_rings: u32,
    // Switches/Routers
    switches: [TB_MAX_SWITCHES]?TbSwitch,
    nr_switches: u32,
    host_switch: u32,
    // Tunnels
    tunnels: [TB_MAX_TUNNELS]TbTunnel,
    nr_tunnels: u32,
    // Bandwidth groups
    bw_groups: [8]TbBandwidthGroup,
    nr_bw_groups: u32,
    // Connection manager
    cm_type: CmType,
    // Security
    auth: TbAuthorization,
    // Power
    power: TbPowerManagement,
    // NVM
    nvm: TbNvm,
    // Discovery
    discovered: bool,
    // Stats
    interrupts: u64,
    errors: u64,
    hotplug_events: u64,

    pub fn init(self: *TbController) void {
        self.discovered = false;
        self.nr_switches = 0;
        self.nr_tunnels = 0;
        self.power.state = .active;
        self.errors = 0;
    }

    pub fn find_switch_by_route(self: *TbController, route: u64) ?*TbSwitch {
        for (&self.switches) |*maybe_sw| {
            if (maybe_sw.*) |*sw| {
                if (sw.route == route) return sw;
            }
        }
        return null;
    }

    pub fn find_free_tunnel_slot(self: *TbController) ?u32 {
        if (self.nr_tunnels >= TB_MAX_TUNNELS) return null;
        return self.nr_tunnels;
    }

    pub fn total_allocated_bw(self: *const TbController) u64 {
        var total: u64 = 0;
        for (self.tunnels[0..self.nr_tunnels]) |tunnel| {
            if (tunnel.activated) {
                total += tunnel.bandwidth_allocated;
            }
        }
        return total;
    }

    pub fn count_active_tunnels(self: *const TbController, tunnel_type: TunnelType) u32 {
        var count: u32 = 0;
        for (self.tunnels[0..self.nr_tunnels]) |tunnel| {
            if (tunnel.activated and @intFromEnum(tunnel.tunnel_type) == @intFromEnum(tunnel_type)) {
                count += 1;
            }
        }
        return count;
    }

    pub fn get_max_link_speed(self: *const TbController) u32 {
        return switch (self.generation) {
            TB_GEN_THUNDERBOLT3, TB_GEN_USB4_V1 => TB_LINK_SPEED_40,
            TB_GEN_THUNDERBOLT4 => TB_LINK_SPEED_40,
            TB_GEN_THUNDERBOLT5, TB_GEN_USB4_V2 => TB_LINK_SPEED_120,
            else => TB_LINK_SPEED_20,
        };
    }
};

// ============================================================================
// Thunderbolt Network (TBT Networking / DMA transport)
// ============================================================================

pub const TbNetDevice = struct {
    controller: *TbController,
    tunnel_index: u32,
    local_uuid: [16]u8,
    remote_uuid: [16]u8,
    mtu: u32,
    // Ring indices
    tx_ring_index: u8,
    rx_ring_index: u8,
    // Stats
    tx_packets: u64,
    rx_packets: u64,
    tx_bytes: u64,
    rx_bytes: u64,
    tx_errors: u64,
    rx_errors: u64,
    // Login
    local_login: bool,
    remote_login: bool,
    connected: bool,
};

pub const TbNetHeader = extern struct {
    frame_id: u32,
    frame_count: u16,
    frame_size: u16,
    frame_index: u16,
    reserved: u16,
};

// ============================================================================
// Retimer Support
// ============================================================================

pub const TbRetimer = struct {
    index: u8,
    port: u8,
    vendor_id: u16,
    device_id: u16,
    nvm_version: u32,
    //  Authentication
    nvm: TbNvm,
    // Capabilities
    usb4_support: bool,
    tbt3_support: bool,
};

// ============================================================================
// Event / Notification Handling
// ============================================================================

pub const TbEventType = enum(u8) {
    hotplug = 0,
    unplug = 1,
    dp_bw_change = 2,
    tunnel_error = 3,
    security_alert = 4,
    power_event = 5,
    nvm_auth_complete = 6,
    link_speed_change = 7,
    clx_transition = 8,
    // Zxyphor
    zxy_qos_violation = 200,
    zxy_anomaly = 201,
};

pub const TbEvent = struct {
    event_type: TbEventType,
    timestamp: u64,
    controller_id: u32,
    switch_route: u64,
    port_number: u8,
    data: [64]u8,
    data_len: u32,
};

pub const TbEventQueue = struct {
    events: [256]TbEvent,
    head: u32,
    tail: u32,

    pub fn push(self: *TbEventQueue, event: TbEvent) bool {
        const next_tail = (self.tail + 1) % 256;
        if (next_tail == self.head) return false;
        self.events[self.tail] = event;
        self.tail = next_tail;
        return true;
    }

    pub fn pop(self: *TbEventQueue) ?TbEvent {
        if (self.head == self.tail) return null;
        const event = self.events[self.head];
        self.head = (self.head + 1) % 256;
        return event;
    }

    pub fn is_empty(self: *const TbEventQueue) bool {
        return self.head == self.tail;
    }
};

// ============================================================================
// USB4 Margin / Link Testing
// ============================================================================

pub const Usb4MarginParams = struct {
    receiver: u8,        // 0 or 1
    mode: MarginMode,
    lanes: u8,           // Bitmask
    voltage_steps: u8,
    timing_steps: u8,
    // Results
    voltage_margin: [2]i16,  // Per lane
    timing_margin: [2]i16,
    eye_height: [2]u16,
    eye_width: [2]u16,
    error_count: [2]u32,
};

pub const MarginMode = enum(u8) {
    voltage = 0,
    timing = 1,
    both = 2,
};

// ============================================================================
// Thunderbolt Subsystem Manager
// ============================================================================

pub const TbSubsystem = struct {
    controllers: [TB_MAX_CONTROLLERS]?TbController,
    nr_controllers: u32,
    event_queue: TbEventQueue,
    security_global: TbSecurityLevel,
    // Retimers
    retimers: [16]TbRetimer,
    nr_retimers: u32,
    // Global state
    initialized: bool,
    suspended: bool,
    // Policy
    auto_approve: bool,
    pcie_tunneling: bool,
    dp_tunneling: bool,
    usb3_tunneling: bool,
    dma_tunneling: bool,

    pub fn init(self: *TbSubsystem) void {
        self.nr_controllers = 0;
        self.nr_retimers = 0;
        self.initialized = true;
        self.suspended = false;
        self.auto_approve = false;
        self.pcie_tunneling = true;
        self.dp_tunneling = true;
        self.usb3_tunneling = true;
        self.dma_tunneling = true;
        self.security_global = .user;
    }

    pub fn find_controller(self: *TbSubsystem, id: u32) ?*TbController {
        for (&self.controllers) |*maybe_ctrl| {
            if (maybe_ctrl.*) |*ctrl| {
                if (ctrl.controller_id == id) return ctrl;
            }
        }
        return null;
    }

    pub fn total_switches(self: *const TbSubsystem) u32 {
        var total: u32 = 0;
        for (self.controllers) |maybe_ctrl| {
            if (maybe_ctrl) |ctrl| {
                total += ctrl.nr_switches;
            }
        }
        return total;
    }

    pub fn total_tunnels(self: *const TbSubsystem) u32 {
        var total: u32 = 0;
        for (self.controllers) |maybe_ctrl| {
            if (maybe_ctrl) |ctrl| {
                total += ctrl.nr_tunnels;
            }
        }
        return total;
    }
};
