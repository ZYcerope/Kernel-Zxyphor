// Zxyphor Kernel - AMD SVM VMCB (Virtual Machine Control Block),
// Hypercall Interface (KVM, Xen, Hyper-V enlightenments),
// virtio Modern Transport,
// vhost-user Protocol,
// Paravirtualization Interfaces
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

// ============================================================================
// AMD SVM VMCB Control Area (offset 0x000 - 0x3FF)
// ============================================================================

pub const VmcbControlArea = extern struct {
    // Intercept vectors
    cr_rd_intercepts: u32,      // 0x000 CR read intercepts (CR0-15)
    cr_wr_intercepts: u32,      // 0x004 CR write intercepts
    dr_rd_intercepts: u32,      // 0x008 DR read intercepts
    dr_wr_intercepts: u32,      // 0x00C DR write intercepts
    exception_intercepts: u32,  // 0x010 Exception intercepts (bits 0-31 = vectors 0-31)
    intercept_misc1: VmcbIntercept1, // 0x014
    intercept_misc2: VmcbIntercept2, // 0x018
    intercept_misc3: u32,       // 0x01C
    _reserved1: [36]u8,         // 0x020 - 0x043
    pause_filter_thresh: u16,   // 0x03E
    pause_filter_count: u16,    // 0x040
    iopm_base_pa: u64,          // 0x048 I/O Permission Map physical address
    msrpm_base_pa: u64,         // 0x050 MSR Permission Map physical address
    tsc_offset: u64,            // 0x058
    guest_asid: u32,            // 0x058
    tlb_control: TlbControlType, // 0x05C
    virtual_intr: VmcbVirtIntr, // 0x060 (8 bytes)
    interrupt_shadow: u64,      // 0x068
    exitcode: u64,              // 0x070
    exitinfo1: u64,             // 0x078
    exitinfo2: u64,             // 0x080
    exit_int_info: u64,         // 0x088
    np_enable: VmcbNpEnable,    // 0x090
    avic_apic_bar: u64,         // 0x098
    ghcb_gpa: u64,              // 0x0A0
    event_inj: u64,             // 0x0A8
    nested_cr3: u64,            // 0x0B0
    virt_ext: VmcbVirtExt,      // 0x0B8
    clean_bits: VmcbCleanBits,  // 0x0C0
    next_rip: u64,              // 0x0C8
    insn_len: u8,               // 0x0D0
    insn_bytes: [15]u8,         // 0x0D1
    avic_backing_page: u64,     // 0x0E0
    _reserved2: u64,            // 0x0E8
    avic_logical_id: u64,       // 0x0F0
    avic_physical_id: u64,      // 0x0F8
    vmsa_pa: u64,               // 0x108 SEV-ES VMSA
    _reserved3: [720]u8,        // pad to 0x400
};

pub const VmcbIntercept1 = packed struct(u32) {
    intr: bool = false,
    nmi: bool = false,
    smi: bool = false,
    init: bool = false,
    vintr: bool = false,
    cr0_sel_writes: bool = false,
    idtr_reads: bool = false,
    gdtr_reads: bool = false,
    ldtr_reads: bool = false,
    tr_reads: bool = false,
    idtr_writes: bool = false,
    gdtr_writes: bool = false,
    ldtr_writes: bool = false,
    tr_writes: bool = false,
    rdtsc: bool = false,
    rdpmc: bool = false,
    pushf: bool = false,
    popf: bool = false,
    cpuid: bool = false,
    rsm: bool = false,
    iret: bool = false,
    int_n: bool = false,
    invd: bool = false,
    pause: bool = false,
    hlt: bool = false,
    invlpg: bool = false,
    invlpga: bool = false,
    ioio_prot: bool = false,
    msr_prot: bool = false,
    task_switch: bool = false,
    ferr_freeze: bool = false,
    shutdown: bool = false,
};

pub const VmcbIntercept2 = packed struct(u32) {
    vmrun: bool = false,
    vmmcall: bool = false,
    vmload: bool = false,
    vmsave: bool = false,
    stgi: bool = false,
    clgi: bool = false,
    skinit: bool = false,
    rdtscp: bool = false,
    icebp: bool = false,
    wbinvd: bool = false,
    monitor: bool = false,
    mwait: bool = false,
    mwait_armed: bool = false,
    xsetbv: bool = false,
    rdpru: bool = false,
    efer_write_trap: bool = false,
    cr0_write_after_event: bool = false,
    cr1_write_after_event: bool = false,
    cr2_write_after_event: bool = false,
    cr3_write_after_event: bool = false,
    cr4_write_after_event: bool = false,
    cr5_write_after_event: bool = false,
    cr6_write_after_event: bool = false,
    cr7_write_after_event: bool = false,
    cr8_write_after_event: bool = false,
    cr9_write_after_event: bool = false,
    cr10_write_after_event: bool = false,
    cr11_write_after_event: bool = false,
    cr12_write_after_event: bool = false,
    cr13_write_after_event: bool = false,
    cr14_write_after_event: bool = false,
    cr15_write_after_event: bool = false,
};

pub const TlbControlType = enum(u32) {
    do_nothing = 0,
    flush_all = 1,
    flush_guest = 3,
    flush_guest_nonglobal = 7,
};

pub const VmcbVirtIntr = packed struct(u64) {
    v_tpr: u8,
    v_irq: bool,
    vgif_value: bool,
    _reserved1: u6,
    v_intr_prio: u4,
    v_ign_tpr: bool,
    _reserved2: u3,
    v_intr_masking: bool,
    vgif_enable: bool,
    _reserved3: u5,
    avic_enable: bool,
    v_intr_vector: u8,
    _reserved4: u24,
};

pub const VmcbNpEnable = packed struct(u64) {
    np_enable: bool,
    sev_enable: bool,
    sev_es_enable: bool,
    gmet: bool,
    sss_check: bool,
    virt_trans_enc: bool,
    _reserved: u58,
};

pub const VmcbVirtExt = packed struct(u64) {
    lbr_virt: bool,
    virt_vmsave_vmload: bool,
    _reserved: u62,
};

pub const VmcbCleanBits = packed struct(u32) {
    intercepts: bool = false,
    iopm: bool = false,
    asid: bool = false,
    tpr: bool = false,
    np: bool = false,
    crx: bool = false,
    drx: bool = false,
    dt: bool = false,
    seg: bool = false,
    cr2: bool = false,
    lbr: bool = false,
    avic: bool = false,
    cet: bool = false,
    _reserved: u19 = 0,
};

// ============================================================================
// VMCB State Save Area (offset 0x400 - 0xFFF)
// ============================================================================

pub const VmcbStateSave = extern struct {
    es: VmcbSegment,            // 0x400
    cs: VmcbSegment,            // 0x410
    ss: VmcbSegment,            // 0x420
    ds: VmcbSegment,            // 0x430
    fs: VmcbSegment,            // 0x440
    gs: VmcbSegment,            // 0x450
    gdtr: VmcbSegment,          // 0x460
    ldtr: VmcbSegment,          // 0x470
    idtr: VmcbSegment,          // 0x480
    tr: VmcbSegment,            // 0x490
    _reserved1: [43]u8,         // 0x4A0
    cpl: u8,                    // 0x4CB
    _reserved2: u32,            // 0x4CC
    efer: u64,                  // 0x4D0
    _reserved3: [112]u8,        // 0x4D8
    cr4: u64,                   // 0x548
    cr3: u64,                   // 0x550
    cr0: u64,                   // 0x558
    dr7: u64,                   // 0x560
    dr6: u64,                   // 0x568
    rflags: u64,                // 0x570
    rip: u64,                   // 0x578
    _reserved4: [88]u8,         // 0x580
    rsp: u64,                   // 0x5D8
    s_cet: u64,                 // 0x5E0
    ssp: u64,                   // 0x5E8
    isst_addr: u64,             // 0x5F0
    rax: u64,                   // 0x5F8
    star: u64,                  // 0x600
    lstar: u64,                 // 0x608
    cstar: u64,                 // 0x610
    sfmask: u64,                // 0x618
    kernel_gs_base: u64,        // 0x620
    sysenter_cs: u64,           // 0x628
    sysenter_esp: u64,          // 0x630
    sysenter_eip: u64,          // 0x638
    cr2: u64,                   // 0x640
    _reserved5: [32]u8,         // 0x648
    g_pat: u64,                 // 0x668
    dbgctl: u64,                // 0x670
    br_from: u64,               // 0x678
    br_to: u64,                 // 0x680
    last_excp_from: u64,        // 0x688
    last_excp_to: u64,          // 0x690
    _reserved6: [72]u8,         // 0x698
    spec_ctrl: u64,             // 0x6E0
};

pub const VmcbSegment = extern struct {
    selector: u16,
    attrib: u16,
    limit: u32,
    base: u64,
};

// ============================================================================
// SVM Exit Codes
// ============================================================================

pub const SvmExitCode = enum(u64) {
    cr0_read = 0x000,
    cr3_read = 0x003,
    cr4_read = 0x004,
    cr8_read = 0x008,
    cr0_write = 0x010,
    cr3_write = 0x013,
    cr4_write = 0x014,
    cr8_write = 0x018,
    dr0_read = 0x020,
    dr0_write = 0x030,
    excp_de = 0x040,
    excp_db = 0x041,
    excp_bp = 0x043,
    excp_of = 0x044,
    excp_br = 0x045,
    excp_ud = 0x046,
    excp_nm = 0x047,
    excp_df = 0x048,
    excp_ts = 0x04A,
    excp_np = 0x04B,
    excp_ss = 0x04C,
    excp_gp = 0x04D,
    excp_pf = 0x04E,
    excp_mf = 0x050,
    excp_ac = 0x051,
    excp_mc = 0x052,
    excp_xf = 0x053,
    intr = 0x060,
    nmi = 0x061,
    smi = 0x062,
    init = 0x063,
    vintr = 0x064,
    cr0_sel_write = 0x065,
    cpuid = 0x072,
    hlt = 0x078,
    invlpg = 0x079,
    invlpga = 0x07A,
    ioio = 0x07B,
    msr = 0x07C,
    task_switch = 0x07D,
    shutdown = 0x07F,
    vmrun = 0x080,
    vmmcall = 0x081,
    vmload = 0x082,
    vmsave = 0x083,
    stgi = 0x084,
    clgi = 0x085,
    skinit = 0x086,
    rdtscp = 0x087,
    icebp = 0x088,
    wbinvd = 0x089,
    monitor = 0x08A,
    mwait = 0x08B,
    mwait_cond = 0x08C,
    xsetbv = 0x08D,
    rdpru = 0x08E,
    efer_write_trap = 0x08F,
    npf = 0x400,         // Nested Page Fault
    avic_incomplete_ipi = 0x401,
    avic_noaccel = 0x402,
    vmgexit = 0x403,
    invalid = 0xFFFFFFFFFFFFFFFF,
};

// ============================================================================
// Hypercall Interface
// ============================================================================

pub const HypercallInterface = enum(u8) {
    kvm = 0,
    xen = 1,
    hyperv = 2,
    zxyphor_native = 3,
};

// KVM Hypercalls
pub const KvmHypercall = enum(u32) {
    vapic_poll_irq = 1,
    mmu_op = 2,
    features = 3,
    pv_eoi = 4,
    kick_cpu = 5,
    hc_send_ipi = 6,
    sched_yield = 7,
    map_gpa_range = 8,
};

pub const KvmCpuidFeatures = packed struct(u32) {
    clocksource = 0x00000001,
    nop_io_delay = 0x00000002,
    mmu_op = 0x00000004,
    clocksource2 = 0x00000008,
    async_pf = 0x00000010,
    steal_time = 0x00000020,
    pv_eoi = 0x00000040,
    pv_unhalt = 0x00000080,
    pv_tlb_flush = 0x00000200,
    async_pf_vmexit = 0x00000400,
    pv_send_ipi = 0x00000800,
    poll_control = 0x00001000,
    pv_sched_yield = 0x00002000,
    async_pf_int = 0x00004000,
    msi_ext_dest_id = 0x00008000,
};

// Hyper-V Enlightenments
pub const HypervEnlightenment = packed struct(u32) {
    vp_runtime_msr = 0x00000001,
    time_ref_count = 0x00000002,
    reference_tsc = 0x00000004,
    apic_access = 0x00000008,
    hypercall_page = 0x00000010,
    vp_index = 0x00000020,
    reset_msr = 0x00000040,
    stat_pages = 0x00000080,
    ref_tsc_invariant = 0x00000100,
    idle_msr = 0x00000200,
    timer_freq_msrs = 0x00000400,
    debug_msrs = 0x00000800,
};

// ============================================================================
// Virtio Modern Transport (MMIO + PCI)
// ============================================================================

pub const VirtioDeviceStatus = packed struct(u8) {
    acknowledge: bool = false,
    driver: bool = false,
    driver_ok: bool = false,
    features_ok: bool = false,
    device_needs_reset: bool = false,
    failed: bool = false,
    _reserved: u2 = 0,
};

pub const VirtioPciCap = extern struct {
    cap_vndr: u8,       // 0x09
    cap_next: u8,
    cap_len: u8,
    cfg_type: VirtioPciCapType,
    bar: u8,
    id: u8,
    padding: [2]u8,
    offset: u32,
    length: u32,
};

pub const VirtioPciCapType = enum(u8) {
    common_cfg = 1,
    notify_cfg = 2,
    isr_cfg = 3,
    device_cfg = 4,
    pci_cfg = 5,
    shared_memory_cfg = 8,
    vendor_cfg = 9,
};

pub const VirtioPciCommonCfg = extern struct {
    device_feature_select: u32,
    device_feature: u32,
    driver_feature_select: u32,
    driver_feature: u32,
    msix_config: u16,
    num_queues: u16,
    device_status: u8,
    config_generation: u8,
    queue_select: u16,
    queue_size: u16,
    queue_msix_vector: u16,
    queue_enable: u16,
    queue_notify_off: u16,
    queue_desc: u64,
    queue_driver: u64,   // avail ring
    queue_device: u64,   // used ring
    queue_notify_data: u16,
    queue_reset: u16,
};

pub const VirtqDesc = extern struct {
    addr: u64,
    len: u32,
    flags: VirtqDescFlags,
    next: u16,
};

pub const VirtqDescFlags = packed struct(u16) {
    next: bool = false,
    write: bool = false,
    indirect: bool = false,
    _reserved: u13 = 0,
};

pub const VirtqAvail = extern struct {
    flags: u16,
    idx: u16,
    ring: [256]u16,
    used_event: u16,
};

pub const VirtqUsed = extern struct {
    flags: u16,
    idx: u16,
    ring: [256]VirtqUsedElem,
    avail_event: u16,
};

pub const VirtqUsedElem = extern struct {
    id: u32,
    len: u32,
};

// ============================================================================
// vhost-user Protocol
// ============================================================================

pub const VHOST_USER_PROTOCOL_F_MQ: u64 = 0;
pub const VHOST_USER_PROTOCOL_F_LOG_SHMFD: u64 = 1;
pub const VHOST_USER_PROTOCOL_F_RARP: u64 = 2;
pub const VHOST_USER_PROTOCOL_F_REPLY_ACK: u64 = 3;
pub const VHOST_USER_PROTOCOL_F_NET_MTU: u64 = 4;
pub const VHOST_USER_PROTOCOL_F_BACKEND_REQ: u64 = 5;
pub const VHOST_USER_PROTOCOL_F_CROSS_ENDIAN: u64 = 6;
pub const VHOST_USER_PROTOCOL_F_CRYPTO_SESSION: u64 = 7;
pub const VHOST_USER_PROTOCOL_F_PAGEFAULT: u64 = 8;
pub const VHOST_USER_PROTOCOL_F_CONFIG: u64 = 9;
pub const VHOST_USER_PROTOCOL_F_BACKEND_SEND_FD: u64 = 10;
pub const VHOST_USER_PROTOCOL_F_HOST_NOTIFIER: u64 = 11;
pub const VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD: u64 = 12;
pub const VHOST_USER_PROTOCOL_F_STATUS: u64 = 14;

pub const VhostUserRequest = enum(u32) {
    none = 0,
    get_features = 1,
    set_features = 2,
    set_owner = 3,
    reset_owner = 4,
    set_mem_table = 5,
    set_log_base = 6,
    set_log_fd = 7,
    set_vring_num = 8,
    set_vring_addr = 9,
    set_vring_base = 10,
    get_vring_base = 11,
    set_vring_kick = 12,
    set_vring_call = 13,
    set_vring_err = 14,
    get_protocol_features = 15,
    set_protocol_features = 16,
    get_queue_num = 17,
    set_vring_enable = 18,
    send_rarp = 19,
    net_set_mtu = 20,
    set_backend_req_fd = 21,
    iotlb_msg = 22,
    set_vring_endian = 23,
    get_config = 24,
    set_config = 25,
    create_crypto_session = 26,
    close_crypto_session = 27,
    postcopy_advise = 28,
    postcopy_listen = 29,
    postcopy_end = 30,
    get_inflight_fd = 31,
    set_inflight_fd = 32,
    gpu_set_socket = 33,
    reset_device = 34,
    vring_kick = 35,
    get_max_mem_slots = 36,
    add_mem_reg = 37,
    rem_mem_reg = 38,
    set_status = 39,
    get_status = 40,
};

pub const VhostUserMsgHeader = extern struct {
    request: u32,
    flags: u32,
    size: u32,
};

pub const VhostUserMemoryRegion = extern struct {
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    mmap_offset: u64,
};

// ============================================================================
// Virt Manager (Zxyphor)
// ============================================================================

pub const VirtSubsystemManager = struct {
    svm_supported: bool,
    vmx_supported: bool,
    sev_supported: bool,
    sev_es_supported: bool,
    avic_supported: bool,
    npt_supported: bool,
    vcpu_count: u32,
    vm_count: u32,
    virtio_devices: u32,
    vhost_user_connections: u32,
    hypercall_interface: HypercallInterface,
    initialized: bool,

    pub fn init() VirtSubsystemManager {
        return std.mem.zeroes(VirtSubsystemManager);
    }
};
