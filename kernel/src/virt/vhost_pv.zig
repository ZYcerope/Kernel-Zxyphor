// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Virtio-FS, Vhost-Net, Vhost-User, Vhost-SCSI,
// Hypervisor Guest Interface, Paravirtualization
// More advanced than Linux 2026 virtualization interfaces

const std = @import("std");

// ============================================================================
// Virtio-FS (Filesystem Passthrough)
// ============================================================================

/// Virtio-FS device config
pub const VirtioFsConfig = struct {
    tag: [36]u8,           // Filesystem tag
    num_request_queues: u32,
};

/// FUSE operation code (used by virtio-fs)
pub const FuseOpcode = enum(u32) {
    lookup = 1,
    forget = 2,
    getattr = 3,
    setattr = 4,
    readlink = 5,
    symlink = 6,
    mknod = 8,
    mkdir = 9,
    unlink = 10,
    rmdir = 11,
    rename = 12,
    link = 13,
    open = 14,
    read = 15,
    write = 16,
    statfs = 17,
    release = 18,
    fsync = 20,
    setxattr = 21,
    getxattr = 22,
    listxattr = 23,
    removexattr = 24,
    flush = 25,
    init = 26,
    opendir = 27,
    readdir = 28,
    releasedir = 29,
    fsyncdir = 30,
    getlk = 31,
    setlk = 32,
    setlkw = 33,
    access = 34,
    create = 35,
    interrupt = 36,
    bmap = 37,
    destroy = 38,
    ioctl = 39,
    poll = 40,
    notify_reply = 41,
    batch_forget = 42,
    fallocate = 43,
    readdirplus = 44,
    rename2 = 45,
    lseek = 46,
    copy_file_range = 47,
    setupmapping = 48,
    removemapping = 49,
    syncfs = 50,
    tmpfile = 51,
    // Zxyphor extensions
    zxy_snapshot = 100,
    zxy_dedup = 101,
    zxy_compress = 102,
};

/// FUSE init flags
pub const FuseInitFlags = packed struct {
    async_read: bool = false,
    posix_locks: bool = false,
    file_ops: bool = false,
    atomic_o_trunc: bool = false,
    export_support: bool = false,
    big_writes: bool = false,
    dont_mask: bool = false,
    splice_write: bool = false,
    splice_move: bool = false,
    splice_read: bool = false,
    flock_locks: bool = false,
    has_ioctl_dir: bool = false,
    auto_inval_data: bool = false,
    do_readdirplus: bool = false,
    readdirplus_auto: bool = false,
    async_dio: bool = false,
    writeback_cache: bool = false,
    no_open_support: bool = false,
    parallel_dirops: bool = false,
    handle_killpriv: bool = false,
    posix_acl: bool = false,
    abort_error: bool = false,
    max_pages: bool = false,
    cache_symlinks: bool = false,
    no_opendir_support: bool = false,
    explicit_inval_data: bool = false,
    map_alignment: bool = false,
    submounts: bool = false,
    handle_killpriv_v2: bool = false,
    setxattr_ext: bool = false,
    init_ext: bool = false,
    init_reserved: bool = false,
};

/// Virtio-FS DAX mapping
pub const VirtioFsDaxMapping = struct {
    inode: u64,
    foffset: u64, // File offset
    moffset: u64, // Mapping offset (in DAX window)
    len: u64,
    flags: u32,
};

/// Virtio-FS instance
pub const VirtioFsInstance = struct {
    tag: [36]u8,
    // Queues
    nr_queues: u32,
    // DAX window
    dax_enabled: bool,
    dax_window_base: u64,
    dax_window_size: u64,
    nr_dax_mappings: u32,
    // FUSE
    fuse_major: u32,
    fuse_minor: u32,
    max_readahead: u32,
    max_write: u32,
    max_pages: u16,
    // Features
    writeback_cache: bool,
    posix_acl: bool,
    // Stats
    total_requests: u64,
    total_reads: u64,
    total_writes: u64,
    total_lookups: u64,
    total_cache_hits: u64,
    avg_latency_ns: u64,
};

// ============================================================================
// Vhost Framework
// ============================================================================

/// Vhost backend type
pub const VhostBackendType = enum(u8) {
    kernel = 0,      // vhost-net in kernel
    user = 1,        // vhost-user (userspace backend)
    vdpa = 2,        // vDPA (virtio Data Path Acceleration)
};

/// Vhost features
pub const VhostFeatures = packed struct {
    // Standard virtio features
    notify_on_empty: bool = false,
    any_layout: bool = false,
    log_all: bool = false,
    // Vhost-user specific
    user_protocol: bool = false,
    user_reply_ack: bool = false,
    user_slave_req: bool = false,
    user_cross_endian: bool = false,
    // Net features
    net_mergeable_rxbufs: bool = false,
    net_mq: bool = false,
    net_guest_announce: bool = false,
    // SCSI
    scsi_multiqueue: bool = false,
    // Zxyphor
    zxy_zero_copy_tx: bool = false,
    zxy_batch_notify: bool = false,
    _padding: u3 = 0,
};

/// Vhost memory region
pub const VhostMemRegion = struct {
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    mmap_offset: u64,
    flags: u32,
};

/// Vhost virtqueue state
pub const VhostVqState = struct {
    index: u16,
    num: u16,       // Queue size
    // Ring addresses
    desc_addr: u64,
    avail_addr: u64,
    used_addr: u64,
    // Kick/call
    kick_fd: i32,
    call_fd: i32,
    err_fd: i32,
    // State
    enabled: bool,
    ready: bool,
    // Stats
    total_requests: u64,
    total_bytes: u64,
    total_kicks: u64,
    total_calls: u64,
};

// ============================================================================
// Vhost-Net
// ============================================================================

/// Vhost-net configuration
pub const VhostNetConfig = struct {
    // Backend
    backend: VhostBackendType,
    // TAP fd
    tap_fd: i32,
    // Features
    features: u64,
    // Queues
    nr_queues: u16,
    // Zero-copy TX
    zero_copy_tx: bool,
    // Polling
    busyloop_timeout: u32, // nanoseconds
    // Stats
    total_tx_packets: u64,
    total_rx_packets: u64,
    total_tx_bytes: u64,
    total_rx_bytes: u64,
    total_tx_kicks: u64,
    total_rx_kicks: u64,
    tx_batched: u64,
    rx_batched: u64,
};

// ============================================================================
// Vhost-User Protocol
// ============================================================================

/// Vhost-user request type
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

/// Vhost-user protocol features
pub const VhostUserProtocolFeatures = packed struct {
    mq: bool = false,
    log_shmfd: bool = false,
    rarp: bool = false,
    reply_ack: bool = false,
    mtu: bool = false,
    backend_req: bool = false,
    cross_endian: bool = false,
    crypto_session: bool = false,
    pagefault: bool = false,
    config: bool = false,
    backend_send_fd: bool = false,
    host_notifier: bool = false,
    inflight_shmfd: bool = false,
    reset_device: bool = false,
    inband_notifications: bool = false,
    configure_mem_slots: bool = false,
    status: bool = false, // device status
    _padding: u15 = 0,
};

/// Vhost-user message header
pub const VhostUserMsgHeader = struct {
    request: VhostUserRequest,
    flags: u32,
    size: u32,
};

// ============================================================================
// Vhost-SCSI
// ============================================================================

/// Vhost-SCSI target
pub const VhostScsiTarget = struct {
    abi_version: i32,
    vhost_wwpn: [224]u8, // World Wide Port Name
    vhost_tpgt: u16,
    // Stats
    total_commands: u64,
    total_data_bytes: u64,
};

// ============================================================================
// vDPA (Virtio Data Path Acceleration)
// ============================================================================

/// vDPA device type
pub const VdpaDeviceType = enum(u8) {
    net = 1,
    block = 2,
    // Zxyphor
    zxy_custom = 100,
};

/// vDPA device configuration
pub const VdpaDevice = struct {
    name: [64]u8,
    device_type: VdpaDeviceType,
    // Virtio
    device_id: u32,
    vendor_id: u32,
    // Features
    device_features: u64,
    driver_features: u64,
    // Queues
    nr_vqs: u16,
    max_vq_size: u16,
    // Config space
    config_size: u32,
    // IOMMU
    has_iommu: bool,
    // Management
    mgmtdev_name: [64]u8,
    // Stats
    total_requests: u64,
};

// ============================================================================
// Hypervisor Guest Interface
// ============================================================================

/// Hypervisor type detection
pub const HypervisorType = enum(u8) {
    none = 0,
    kvm = 1,
    xen = 2,
    vmware = 3,
    hyperv = 4,
    virtualbox = 5,
    qemu = 6,
    bhyve = 7,
    acrn = 8,
    // Zxyphor
    zxyphor = 50,
};

/// Hypervisor CPUID signature
pub const HvCpuidSignature = struct {
    max_leaf: u32,
    signature: [12]u8,
};

/// Known signatures
pub const HV_SIG_KVMKVMKVM: [12]u8 = "KVMKVMKVM\x00\x00\x00".*;
pub const HV_SIG_VMWAREVM: [12]u8 = "VMwareVMware".*;
pub const HV_SIG_MICROSOFTHV: [12]u8 = "Microsoft Hv".*;
pub const HV_SIG_XENVMMXENVM: [12]u8 = "XenVMMXenVMM".*;
pub const HV_SIG_ZXYPHORHV: [12]u8 = "ZxyphorHyprv".*;

/// KVM paravirt features (CPUID 0x40000001)
pub const KvmPvFeatures = packed struct {
    clocksource: bool = false,
    nop_io_delay: bool = false,
    mmu_op: bool = false,
    clocksource2: bool = false,
    async_pf: bool = false,
    steal_time: bool = false,
    pv_eoi: bool = false,
    pv_unhalt: bool = false,
    _reserved1: u1 = 0,
    pv_tlb_flush: bool = false,
    async_pf_vmexit: bool = false,
    pv_send_ipi: bool = false,
    poll_control: bool = false,
    pv_sched_yield: bool = false,
    async_pf_int: bool = false,
    msi_ext_dest_id: bool = false,
    hc_map_gpa_range: bool = false,
    migration: bool = false,
    _padding: u14 = 0,
};

/// KVM steal time
pub const KvmStealTime = struct {
    steal: u64,
    version: u32,
    flags: u32,
    preempted: u8,
    _padding: [3]u8,
};

/// KVM clock MSRs
pub const KVM_MSR_SYSTEM_TIME: u32 = 0x4b564d01;
pub const KVM_MSR_WALL_CLOCK: u32 = 0x4b564d00;
pub const KVM_MSR_SYSTEM_TIME_NEW: u32 = 0x4b564d01;
pub const KVM_MSR_WALL_CLOCK_NEW: u32 = 0x4b564d00;
pub const KVM_MSR_ASYNC_PF_EN: u32 = 0x4b564d02;
pub const KVM_MSR_STEAL_TIME: u32 = 0x4b564d03;
pub const KVM_MSR_PV_EOI_EN: u32 = 0x4b564d04;
pub const KVM_MSR_ASYNC_PF_INT: u32 = 0x4b564d06;
pub const KVM_MSR_ASYNC_PF_ACK: u32 = 0x4b564d07;

/// Hyper-V features
pub const HypervFeatures = packed struct {
    vp_runtime: bool = false,
    time_ref_count: bool = false,
    synic: bool = false,
    syntimers: bool = false,
    apic: bool = false,
    hypercall: bool = false,
    vp_index: bool = false,
    reset: bool = false,
    stats: bool = false,
    ref_tsc: bool = false,
    guest_idle: bool = false,
    timer_freq: bool = false,
    guest_debug: bool = false,
    reenlightenment: bool = false,
    stimer_direct: bool = false,
    _padding: u17 = 0,
};

/// Hyper-V hypercall page
pub const HypervHypercallPage = struct {
    enabled: bool,
    guest_physical_address: u64,
};

// ============================================================================
// Paravirt operations
// ============================================================================

/// Paravirt operation types
pub const PvOpsType = enum(u8) {
    // Time
    sched_clock = 0,
    steal_clock = 1,
    // CPU
    cpuid = 10,
    get_debugreg = 11,
    set_debugreg = 12,
    read_cr0 = 13,
    write_cr0 = 14,
    // Memory
    flush_tlb = 20,
    set_pte = 21,
    set_pmd = 22,
    set_pud = 23,
    set_p4d = 24,
    // Interrupts
    save_fl = 30,
    restore_fl = 31,
    irq_disable = 32,
    irq_enable = 33,
    // Lock
    queued_spin_lock_slowpath = 40,
    queued_spin_unlock = 41,
    vcpu_is_preempted = 42,
    // MMU
    mmu_update = 50,
    mmu_ext_op = 51,
    // Zxyphor
    zxy_fast_hypercall = 100,
};

/// Paravirt patching info
pub const PvPatchSite = struct {
    instrtype: PvOpsType,
    clobbers: u32,
    len: u32,
    addr: u64,
};

// ============================================================================
// Balloon Driver
// ============================================================================

/// Virtio balloon configuration
pub const VirtioBalloonConfig = struct {
    num_pages: u32,      // Number of pages host wants
    actual: u32,         // Actual number of pages we have
    // Reporting
    free_page_hint_cmd_id: u32,
    poison_val: u32,
};

/// Balloon features
pub const BalloonFeatures = packed struct {
    must_tell_host: bool = false,
    stats_vq: bool = false,
    deflate_on_oom: bool = false,
    free_page_hint: bool = false,
    page_poison: bool = false,
    page_reporting: bool = false,
    // Zxyphor
    zxy_adaptive: bool = false,
    _padding: u1 = 0,
};

/// Balloon statistics
pub const BalloonStats = struct {
    swap_in: u64,
    swap_out: u64,
    major_faults: u64,
    minor_faults: u64,
    free_memory: u64,
    total_memory: u64,
    available_memory: u64,
    disk_caches: u64,
    hugetlb_allocations: u64,
    hugetlb_failures: u64,
    // Balloon state
    inflated_pages: u64,
    deflated_pages: u64,
    total_inflate_ops: u64,
    total_deflate_ops: u64,
};

// ============================================================================
// VSOCK (Virtio Sockets)
// ============================================================================

/// VSOCK transport type
pub const VsockTransport = enum(u8) {
    virtio = 0,
    vmci = 1,
    hyperv = 2,
    loopback = 3,
    // Zxyphor
    zxy_fast = 10,
};

/// VSOCK configuration
pub const VsockConfig = struct {
    guest_cid: u64,
    // Transport
    transport: VsockTransport,
    // Limits
    max_buffer_size: u64,
    default_buffer_size: u64,
    min_buffer_size: u64,
    // Stats
    total_connections: u64,
    total_rx_bytes: u64,
    total_tx_bytes: u64,
    total_rx_packets: u64,
    total_tx_packets: u64,
};

/// Well-known CIDs
pub const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
pub const VMADDR_CID_HYPERVISOR: u32 = 0;
pub const VMADDR_CID_LOCAL: u32 = 1;
pub const VMADDR_CID_HOST: u32 = 2;

// ============================================================================
// Subsystem Manager
// ============================================================================

/// Virtualization interface subsystem
pub const VirtSubsystem = struct {
    // Hypervisor detection
    hypervisor: HypervisorType,
    hv_signature: [12]u8,
    // Paravirt
    pv_enabled: bool,
    pv_clock: bool,
    pv_steal_time: bool,
    pv_eoi: bool,
    pv_ipi: bool,
    pv_spinlock: bool,
    // Virtio-FS
    nr_virtiofs: u32,
    // Vhost
    nr_vhost_net: u32,
    nr_vhost_scsi: u32,
    nr_vhost_user: u32,
    // vDPA
    nr_vdpa: u32,
    // Balloon
    balloon_enabled: bool,
    balloon_pages: u64,
    // VSOCK
    vsock_enabled: bool,
    vsock_cid: u64,
    // Stats
    total_hypercalls: u64,
    total_vmexits: u64,
    // Zxyphor
    zxy_fast_pv: bool,
    zxy_nested_opt: bool,
    initialized: bool,

    pub fn init() VirtSubsystem {
        return VirtSubsystem{
            .hypervisor = .none,
            .hv_signature = std.mem.zeroes([12]u8),
            .pv_enabled = false,
            .pv_clock = false,
            .pv_steal_time = false,
            .pv_eoi = false,
            .pv_ipi = false,
            .pv_spinlock = false,
            .nr_virtiofs = 0,
            .nr_vhost_net = 0,
            .nr_vhost_scsi = 0,
            .nr_vhost_user = 0,
            .nr_vdpa = 0,
            .balloon_enabled = false,
            .balloon_pages = 0,
            .vsock_enabled = false,
            .vsock_cid = 0,
            .total_hypercalls = 0,
            .total_vmexits = 0,
            .zxy_fast_pv = true,
            .zxy_nested_opt = true,
            .initialized = false,
        };
    }
};
