// SPDX-License-Identifier: MIT
// Zxyphor Kernel - InfiniBand/RDMA Subsystem
// Comprehensive IB verbs, QP, CQ, MR, PD, SRQ, multicast
// More advanced than Linux 2026 RDMA stack

const std = @import("std");

// ============================================================================
// GID / LID / GUID
// ============================================================================

pub const IB_GID_LEN = 16;
pub const IB_MGID_LEN = 16;

pub const Gid = struct {
    raw: [IB_GID_LEN]u8 = [_]u8{0} ** IB_GID_LEN,

    pub fn subnet_prefix(self: *const Gid) u64 {
        return std.mem.readInt(u64, self.raw[0..8], .big);
    }
    pub fn interface_id(self: *const Gid) u64 {
        return std.mem.readInt(u64, self.raw[8..16], .big);
    }
    pub fn is_zero(self: *const Gid) bool {
        for (self.raw) |b| {
            if (b != 0) return false;
        }
        return true;
    }
};

pub const GidType = enum(u8) {
    ib = 0,
    roce_v1 = 1,
    roce_v2 = 2,
};

pub const GidEntry = struct {
    gid: Gid = .{},
    gid_type: GidType = .ib,
    ndev_ifindex: u32 = 0,
    port_num: u8 = 0,
    gid_index: u16 = 0,
};

// ============================================================================
// Port / Device attributes
// ============================================================================

pub const IbMtu = enum(u32) {
    mtu_256 = 1,
    mtu_512 = 2,
    mtu_1024 = 3,
    mtu_2048 = 4,
    mtu_4096 = 5,
};

pub const IbPortState = enum(u8) {
    nop = 0,
    down = 1,
    init = 2,
    armed = 3,
    active = 4,
    active_defer = 5,
};

pub const IbWidth = enum(u8) {
    w_1x = 1,
    w_2x = 16,
    w_4x = 2,
    w_8x = 4,
    w_12x = 8,
};

pub const IbSpeed = enum(u16) {
    sdr = 1,          // 2.5 Gbps
    ddr = 2,          // 5 Gbps
    qdr = 4,          // 10 Gbps
    fdr10 = 8,        // 10.3125 Gbps
    fdr = 16,         // 14.0625 Gbps
    edr = 32,         // 25.78125 Gbps
    hdr = 64,         // 50 Gbps
    ndr = 128,        // 100 Gbps
    xdr = 256,        // 250 Gbps
    // Zxyphor
    zdr = 512,        // 500 Gbps
};

pub const IbPortCap = packed struct {
    sm: bool = false,
    notice_supported: bool = false,
    trap_supported: bool = false,
    optional_ipd: bool = false,
    auto_migr: bool = false,
    sl_map: bool = false,
    mkey_nvram: bool = false,
    pkey_nvram: bool = false,
    led_info: bool = false,
    sm_disabled: bool = false,
    sys_image_guid: bool = false,
    pkey_switch_ext_port_trap: bool = false,
    cm: bool = false,
    snmp_tunnel: bool = false,
    reinit: bool = false,
    device_mgmt: bool = false,
    vendor_class: bool = false,
    dr_notice: bool = false,
    cap_mask_notice: bool = false,
    boot_mgmt: bool = false,
    link_latency: bool = false,
    client_reg: bool = false,
    ip_based_gids: bool = false,
    _padding: u9 = 0,
};

pub const IbPortAttr = struct {
    state: IbPortState = .down,
    max_mtu: IbMtu = .mtu_4096,
    active_mtu: IbMtu = .mtu_4096,
    gid_tbl_len: u32 = 0,
    port_cap_flags: IbPortCap = .{},
    max_msg_sz: u32 = 0,
    bad_pkey_counter: u32 = 0,
    qkey_viol_counter: u32 = 0,
    pkey_tbl_len: u16 = 0,
    lid: u16 = 0,
    sm_lid: u16 = 0,
    lmc: u8 = 0,
    max_vl_num: u8 = 0,
    sm_sl: u8 = 0,
    subnet_timeout: u8 = 0,
    init_type_reply: u8 = 0,
    active_width: IbWidth = .w_4x,
    active_speed: IbSpeed = .hdr,
    phys_state: u8 = 0,
    grh_required: bool = false,
};

// ============================================================================
// Device capabilities
// ============================================================================

pub const IbDeviceCap = packed struct {
    resize_max_wr: bool = false,
    bad_pkey_counter: bool = false,
    bad_qkey_counter: bool = false,
    raw_multi: bool = false,
    auto_path_mig: bool = false,
    change_phy_port: bool = false,
    ud_av_port_enforce: bool = false,
    curr_qp_state_mod: bool = false,
    ud_ip_csum: bool = false,
    ud_tsO: bool = false,
    xrc: bool = false,
    mem_mgmt: bool = false,
    block_mcast_loopback: bool = false,
    mem_window: bool = false,
    mem_window_type_2a: bool = false,
    mem_window_type_2b: bool = false,
    rc_ip_csum: bool = false,
    raw_ip_csum: bool = false,
    managed_flow_steering: bool = false,
    sig_handover: bool = false,
    on_demand_paging: bool = false,
    sg_fcs_check: bool = false,
    cross_channel: bool = false,
    nvmf_target_offload: bool = false,
    pci_write_end_padding: bool = false,
    scatter_fcs: bool = false,
    allow_user_unreg: bool = false,
    core_cap_ecn: bool = false,
    core_cap_rdma_read: bool = false,
    core_cap_rdma_write: bool = false,
    core_cap_atomic: bool = false,
    _padding: u1 = 0,
};

pub const IbDeviceAttr = struct {
    fw_ver: [64]u8 = [_]u8{0} ** 64,
    sys_image_guid: u64 = 0,
    max_mr_size: u64 = 0,
    page_size_cap: u64 = 0,
    vendor_id: u32 = 0,
    vendor_part_id: u32 = 0,
    hw_ver: u32 = 0,
    max_qp: u32 = 0,
    max_qp_wr: u32 = 0,
    device_cap_flags: IbDeviceCap = .{},
    max_send_sge: u32 = 0,
    max_recv_sge: u32 = 0,
    max_sge_rd: u32 = 0,
    max_cq: u32 = 0,
    max_cqe: u32 = 0,
    max_mr: u32 = 0,
    max_pd: u32 = 0,
    max_qp_rd_atom: u32 = 0,
    max_ee_rd_atom: u32 = 0,
    max_res_rd_atom: u32 = 0,
    max_qp_init_rd_atom: u32 = 0,
    max_ee_init_rd_atom: u32 = 0,
    atomic_cap: IbAtomicCap = .none,
    max_mcast_grp: u32 = 0,
    max_mcast_qp_attach: u32 = 0,
    max_total_mcast_qp_attach: u32 = 0,
    max_ah: u32 = 0,
    max_srq: u32 = 0,
    max_srq_wr: u32 = 0,
    max_srq_sge: u32 = 0,
    max_fast_reg_page_list_len: u32 = 0,
    max_pkeys: u16 = 0,
    local_ca_ack_delay: u8 = 0,
    // ODP caps
    odp_caps: OdpCaps = .{},
    // Timestamp
    timestamp_mask: u64 = 0,
    hca_core_clock: u64 = 0,
    // Device memory
    max_dm_size: u64 = 0,
};

pub const IbAtomicCap = enum(u8) {
    none = 0,
    hca = 1,
    glob = 2,
};

pub const OdpCaps = struct {
    general_caps: u64 = 0,
    per_transport_caps_rc: u32 = 0,
    per_transport_caps_uc: u32 = 0,
    per_transport_caps_ud: u32 = 0,
    per_transport_caps_xrc: u32 = 0,
};

// ============================================================================
// Protection Domain
// ============================================================================

pub const IbPd = struct {
    device_id: u32 = 0,
    handle: u32 = 0,
    local_dma_lkey: u32 = 0,
    unsafe_global_rkey: u32 = 0,
    flags: IbPdFlags = .{},
};

pub const IbPdFlags = packed struct {
    local_dma_lkey: bool = false,
    raw_packet: bool = false,
    _padding: u6 = 0,
};

// ============================================================================
// Completion Queue
// ============================================================================

pub const IbCqFlags = packed struct {
    shared: bool = false,
    timestamp: bool = false,
    ignore_overrun: bool = false,
    _padding: u5 = 0,
};

pub const IbCq = struct {
    device_id: u32 = 0,
    handle: u32 = 0,
    cqe: u32 = 0,           // max CQ entries
    comp_vector: u32 = 0,
    flags: IbCqFlags = .{},
    // Polling
    poll_ctx: IbPollContext = .direct,
    // Stats
    total_completions: u64 = 0,
    total_errors: u64 = 0,
};

pub const IbPollContext = enum(u8) {
    direct = 0,
    softirq = 1,
    workqueue = 2,
    unbound_workqueue = 3,
};

pub const IbWcStatus = enum(u32) {
    success = 0,
    loc_len_err = 1,
    loc_qp_op_err = 2,
    loc_eec_op_err = 3,
    loc_prot_err = 4,
    wr_flush_err = 5,
    mw_bind_err = 6,
    bad_resp_err = 7,
    loc_access_err = 8,
    rem_inv_req_err = 9,
    rem_access_err = 10,
    rem_op_err = 11,
    retry_exc_err = 12,
    rnr_retry_exc_err = 13,
    loc_rdd_viol_err = 14,
    rem_inv_rd_req_err = 15,
    rem_abort_err = 16,
    inv_eecn_err = 17,
    inv_eec_state_err = 18,
    fatal_err = 19,
    resp_timeout_err = 20,
    general_err = 21,
    tag_matching_err = 22,
};

pub const IbWcOpcode = enum(u32) {
    send = 0,
    rdma_write = 1,
    rdma_read = 2,
    comp_swap = 3,
    fetch_add = 4,
    bind_mw = 5,
    lso = 6,
    local_inv = 7,
    reg_mr = 8,
    masked_comp_swap = 9,
    masked_fetch_add = 10,
    recv = 128,
    recv_rdma_with_imm = 129,
    tag_add = 130,
    tag_del = 131,
    tag_sync = 132,
    tag_recv = 133,
    tag_msg = 134,
};

pub const IbWc = struct {
    wr_id: u64 = 0,
    status: IbWcStatus = .success,
    opcode: IbWcOpcode = .send,
    vendor_err: u32 = 0,
    byte_len: u32 = 0,
    qp_num: u32 = 0,
    src_qp: u32 = 0,
    pkey_index: u16 = 0,
    slid: u16 = 0,
    sl: u8 = 0,
    dlid_path_bits: u8 = 0,
    wc_flags: u32 = 0,
    imm_data: u32 = 0,
    invalidate_rkey: u32 = 0,
    // Timestamp
    timestamp_ns: u64 = 0,
};

// ============================================================================
// Queue Pair
// ============================================================================

pub const IbQpType = enum(u8) {
    rc = 2,           // Reliable Connected
    uc = 3,           // Unreliable Connected
    ud = 4,           // Unreliable Datagram
    raw_ipv6 = 5,
    raw_ethertype = 6,
    smi = 7,          // Subnet Management Interface
    gsi = 8,          // General Service Interface
    xrc_ini = 9,      // XRC Initiator
    xrc_tgt = 10,     // XRC Target
    raw_packet = 11,
    // Zxyphor
    zxy_reliable_multicast = 50,
};

pub const IbQpState = enum(u8) {
    reset = 0,
    init = 1,
    rtr = 2,
    rts = 3,
    sqd = 4,
    sqe = 5,
    err = 6,
};

pub const IbAccessFlags = packed struct {
    local_write: bool = false,
    remote_write: bool = false,
    remote_read: bool = false,
    remote_atomic: bool = false,
    mw_bind: bool = false,
    zero_based: bool = false,
    on_demand: bool = false,
    hugetlb: bool = false,
    flush_local: bool = false,
    flush_remote: bool = false,
    _padding: u6 = 0,
};

pub const IbQpAttr = struct {
    qp_state: IbQpState = .reset,
    cur_qp_state: IbQpState = .reset,
    path_mtu: IbMtu = .mtu_4096,
    path_mig_state: u8 = 0,
    qkey: u32 = 0,
    rq_psn: u32 = 0,
    sq_psn: u32 = 0,
    dest_qp_num: u32 = 0,
    qp_access_flags: IbAccessFlags = .{},
    max_rd_atomic: u8 = 0,
    max_dest_rd_atomic: u8 = 0,
    min_rnr_timer: u8 = 0,
    port_num: u8 = 0,
    timeout: u8 = 0,
    retry_cnt: u8 = 0,
    rnr_retry: u8 = 0,
    alt_port_num: u8 = 0,
    alt_timeout: u8 = 0,
    // AH attributes
    ah_attr: IbAhAttr = .{},
    alt_ah_attr: IbAhAttr = .{},
    // Rate limit
    rate_limit: u32 = 0,
};

pub const IbQp = struct {
    device_id: u32 = 0,
    pd_handle: u32 = 0,
    send_cq_handle: u32 = 0,
    recv_cq_handle: u32 = 0,
    srq_handle: u32 = 0,
    qp_num: u32 = 0,
    qp_type: IbQpType = .rc,
    max_send_wr: u32 = 0,
    max_recv_wr: u32 = 0,
    max_send_sge: u32 = 0,
    max_recv_sge: u32 = 0,
    max_inline_data: u32 = 0,
    // Stats
    total_send: u64 = 0,
    total_recv: u64 = 0,
    total_rdma_read: u64 = 0,
    total_rdma_write: u64 = 0,
    total_atomic: u64 = 0,
    total_errors: u64 = 0,
};

// ============================================================================
// Address Handle
// ============================================================================

pub const IbAhAttr = struct {
    grh: IbGrh = .{},
    dlid: u16 = 0,
    sl: u8 = 0,
    src_path_bits: u8 = 0,
    static_rate: u8 = 0,
    port_num: u8 = 0,
    is_global: bool = false,
};

pub const IbGrh = struct {
    dgid: Gid = .{},
    sgid_index: u32 = 0,
    flow_label: u32 = 0,
    hop_limit: u8 = 0,
    traffic_class: u8 = 0,
};

// ============================================================================
// Memory Region
// ============================================================================

pub const IbMr = struct {
    device_id: u32 = 0,
    pd_handle: u32 = 0,
    lkey: u32 = 0,
    rkey: u32 = 0,
    length: u64 = 0,
    iova: u64 = 0,
    access: IbAccessFlags = .{},
    // ODP
    is_odp: bool = false,
    // DMA-MR
    is_dma_mr: bool = false,
    // Type
    mr_type: IbMrType = .normal,
};

pub const IbMrType = enum(u8) {
    normal = 0,
    user = 1,
    dma = 2,
    sig = 3,
    integrity = 4,
    dm = 5,
};

// ============================================================================
// Shared Receive Queue
// ============================================================================

pub const IbSrqType = enum(u8) {
    basic = 0,
    xrc = 1,
    tag_matching = 2,
};

pub const IbSrq = struct {
    device_id: u32 = 0,
    pd_handle: u32 = 0,
    srq_type: IbSrqType = .basic,
    max_wr: u32 = 0,
    max_sge: u32 = 0,
    srq_limit: u32 = 0,
    xrcd_handle: u32 = 0,
    cq_handle: u32 = 0,
};

// ============================================================================
// Send/Recv Work Requests
// ============================================================================

pub const IbWrOpcode = enum(u32) {
    rdma_write = 0,
    rdma_write_with_imm = 1,
    send = 2,
    send_with_imm = 3,
    rdma_read = 4,
    atomic_cmp_and_swp = 5,
    atomic_fetch_and_add = 6,
    lso = 10,
    send_with_inv = 11,
    rdma_read_with_inv = 12,
    local_inv = 13,
    masked_atomic_cmp_and_swp = 14,
    masked_atomic_fetch_and_add = 15,
    bind_mw = 16,
    reg_mr = 17,
    flush = 18,
    atomic_write = 19,
};

pub const IbSendFlags = packed struct {
    fence: bool = false,
    signaled: bool = false,
    solicited: bool = false,
    inline_data: bool = false,
    ip_csum: bool = false,
    _padding: u3 = 0,
};

pub const IbSge = struct {
    addr: u64 = 0,
    length: u32 = 0,
    lkey: u32 = 0,
};

// ============================================================================
// CM (Connection Manager)
// ============================================================================

pub const IbCmEvent = enum(u32) {
    req_received = 0,
    req_error = 1,
    rep_received = 2,
    rep_error = 3,
    rtu_received = 4,
    dreq_received = 5,
    dreq_error = 6,
    drep_received = 7,
    timewait_exit = 8,
    mra_received = 9,
    rej_received = 10,
    lap_received = 11,
    lap_error = 12,
    apr_received = 13,
    sidr_req_received = 14,
    sidr_rep_received = 15,
};

pub const IbCmRejReason = enum(u16) {
    no_qp = 1,
    no_eec = 2,
    no_resources = 3,
    timeout = 4,
    unsupported = 5,
    invalid_comm_id = 6,
    invalid_comm_instance = 7,
    invalid_service_id = 8,
    invalid_transport_type = 9,
    stale_conn = 10,
    rnr_retry = 11,
    duplicate_local_comm_id = 12,
    invalid_class_version = 13,
    invalid_flow_label = 14,
    invalid_alt_flow_label = 15,
    consumer_defined = 28,
};

// ============================================================================
// RDMA CM
// ============================================================================

pub const RdmaCmEvent = enum(u32) {
    addr_resolved = 0,
    addr_error = 1,
    route_resolved = 2,
    route_error = 3,
    connect_request = 4,
    connect_response = 5,
    connect_error = 6,
    unreachable = 7,
    rejected = 8,
    established = 9,
    disconnected = 10,
    device_removal = 11,
    multicast_join = 12,
    multicast_error = 13,
    addr_change = 14,
    timewait_exit = 15,
};

pub const RdmaCmId = struct {
    device_id: u32 = 0,
    local_addr: [16]u8 = [_]u8{0} ** 16,
    remote_addr: [16]u8 = [_]u8{0} ** 16,
    ps: RdmaPortSpace = .tcp,
    qp_type: IbQpType = .rc,
    port_num: u8 = 0,
};

pub const RdmaPortSpace = enum(u16) {
    ipoib = 0x0002,
    ib = 0x013F,
    tcp = 0x0106,
    udp = 0x0111,
};

// ============================================================================
// Multicast
// ============================================================================

pub const IbMcastGroup = struct {
    mgid: Gid = .{},
    mlid: u16 = 0,
    sl: u8 = 0,
    flow_label: u32 = 0,
    hop_limit: u8 = 0,
    traffic_class: u8 = 0,
    pkey: u16 = 0,
    rate: u8 = 0,
    mtu: IbMtu = .mtu_4096,
    scope: u8 = 0,
    join_state: u8 = 0,
};

// ============================================================================
// RoCE (RDMA over Converged Ethernet)
// ============================================================================

pub const RoceVersion = enum(u8) {
    v1 = 1,
    v2 = 2,
};

pub const RoceConfig = struct {
    version: RoceVersion = .v2,
    gid_type: GidType = .roce_v2,
    dscp: u8 = 0,
    ecn: bool = false,
    congestion_control: RoceCongestionAlgo = .dcqcn,
    min_rnr_timer: u8 = 0,
};

pub const RoceCongestionAlgo = enum(u8) {
    dcqcn = 0,
    dctcp = 1,
    timely = 2,
    hpcc = 3,
    swift = 4,
    // Zxyphor
    zxy_adaptive = 10,
};

// ============================================================================
// iWARP (Internet WARP)
// ============================================================================

pub const IwarpCmEvent = enum(u32) {
    connect_request = 0,
    connect_reply = 1,
    established = 2,
    close = 3,
    disconnect = 4,
};

pub const IwarpConfig = struct {
    mpa_version: u8 = 2,
    use_enhanced_rdma: bool = false,
    markers_enabled: bool = false,
    crc_enabled: bool = true,
    ddp_version: u8 = 1,
    rdmap_version: u8 = 1,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const InfiniBandSubsystem = struct {
    // Device stats
    nr_ib_devices: u32 = 0,
    nr_roce_devices: u32 = 0,
    nr_iwarp_devices: u32 = 0,
    // Resources
    nr_protection_domains: u64 = 0,
    nr_queue_pairs: u64 = 0,
    nr_completion_queues: u64 = 0,
    nr_memory_regions: u64 = 0,
    nr_address_handles: u64 = 0,
    nr_shared_recv_queues: u64 = 0,
    // Performance
    total_rdma_read_bytes: u64 = 0,
    total_rdma_write_bytes: u64 = 0,
    total_send_bytes: u64 = 0,
    total_recv_bytes: u64 = 0,
    total_atomic_ops: u64 = 0,
    // Errors
    total_cq_errors: u64 = 0,
    total_qp_errors: u64 = 0,
    total_connection_errors: u64 = 0,
    // Multicast
    nr_multicast_groups: u32 = 0,
    total_multicast_attach: u64 = 0,
    // RoCE
    total_ecn_marked: u64 = 0,
    total_cnp_sent: u64 = 0,
    total_cnp_received: u64 = 0,
    // Zxyphor
    zxy_reliable_multicast_enabled: bool = false,
    initialized: bool = false,
};
