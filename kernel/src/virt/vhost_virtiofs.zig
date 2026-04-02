// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Vhost-User & Virtio-FS Detail
// Complete: vhost-user protocol, vhost-user backend ops, virtqueue management,
// virtio-fs FUSE passthrough, DAX window, migration, vhost-net/blk/scsi

const std = @import("std");

// ============================================================================
// Vhost-User Protocol
// ============================================================================

pub const VhostUserRequestType = enum(u32) {
    VHOST_USER_NONE = 0,
    VHOST_USER_GET_FEATURES = 1,
    VHOST_USER_SET_FEATURES = 2,
    VHOST_USER_SET_OWNER = 3,
    VHOST_USER_RESET_OWNER = 4,
    VHOST_USER_SET_MEM_TABLE = 5,
    VHOST_USER_SET_LOG_BASE = 6,
    VHOST_USER_SET_LOG_FD = 7,
    VHOST_USER_SET_VRING_NUM = 8,
    VHOST_USER_SET_VRING_ADDR = 9,
    VHOST_USER_SET_VRING_BASE = 10,
    VHOST_USER_GET_VRING_BASE = 11,
    VHOST_USER_SET_VRING_KICK = 12,
    VHOST_USER_SET_VRING_CALL = 13,
    VHOST_USER_SET_VRING_ERR = 14,
    VHOST_USER_GET_PROTOCOL_FEATURES = 15,
    VHOST_USER_SET_PROTOCOL_FEATURES = 16,
    VHOST_USER_GET_QUEUE_NUM = 17,
    VHOST_USER_SET_VRING_ENABLE = 18,
    VHOST_USER_SEND_RARP = 19,
    VHOST_USER_NET_SET_MTU = 20,
    VHOST_USER_SET_BACKEND_REQ_FD = 21,
    VHOST_USER_IOTLB_MSG = 22,
    VHOST_USER_SET_VRING_ENDIAN = 23,
    VHOST_USER_GET_CONFIG = 24,
    VHOST_USER_SET_CONFIG = 25,
    VHOST_USER_CREATE_CRYPTO_SESSION = 26,
    VHOST_USER_CLOSE_CRYPTO_SESSION = 27,
    VHOST_USER_POSTCOPY_ADVISE = 28,
    VHOST_USER_POSTCOPY_LISTEN = 29,
    VHOST_USER_POSTCOPY_END = 30,
    VHOST_USER_GET_INFLIGHT_FD = 31,
    VHOST_USER_SET_INFLIGHT_FD = 32,
    VHOST_USER_GPU_SET_SOCKET = 33,
    VHOST_USER_RESET_DEVICE = 34,
    VHOST_USER_VRING_KICK = 35,
    VHOST_USER_GET_MAX_MEM_SLOTS = 36,
    VHOST_USER_ADD_MEM_REG = 37,
    VHOST_USER_REM_MEM_REG = 38,
    VHOST_USER_SET_STATUS = 39,
    VHOST_USER_GET_STATUS = 40,
};

pub const VhostUserBackendRequestType = enum(u32) {
    VHOST_USER_BACKEND_NONE = 0,
    VHOST_USER_BACKEND_IOTLB_MSG = 1,
    VHOST_USER_BACKEND_CONFIG_CHANGE_MSG = 2,
    VHOST_USER_BACKEND_VRING_HOST_NOTIFIER_MSG = 3,
    VHOST_USER_BACKEND_VRING_CALL = 4,
    VHOST_USER_BACKEND_VRING_ERR = 5,
    VHOST_USER_BACKEND_SHARED_OBJECT_ADD = 6,
    VHOST_USER_BACKEND_SHARED_OBJECT_REMOVE = 7,
    VHOST_USER_BACKEND_SHARED_OBJECT_LOOKUP = 8,
};

pub const VhostUserMsgHeader = packed struct(u96) {
    request: u32,
    flags: VhostUserMsgFlags,
    size: u32,
};

pub const VhostUserMsgFlags = packed struct(u32) {
    version: u2,       // Protocol version (currently 1)
    reply: bool,       // Reply flag
    need_reply: bool,  // Need-reply flag
    _reserved: u28,
};

pub const VhostUserProtocolFeatures = packed struct(u64) {
    mq: bool,                    // 0
    log_shmfd: bool,             // 1
    rarp: bool,                  // 2
    reply_ack: bool,             // 3
    mtu: bool,                   // 4
    backend_req: bool,           // 5
    cross_endian: bool,          // 6
    crypto_session: bool,        // 7
    pagefault: bool,             // 8
    config: bool,                // 9
    backend_send_fd: bool,       // 10
    host_notifier: bool,         // 11
    inflight_shmfd: bool,        // 12
    reset_device: bool,          // 13
    inband_notifications: bool,  // 14
    configure_mem_slots: bool,   // 15
    status: bool,                // 16
    shared_object: bool,         // 17
    device_state: bool,          // 18
    _reserved: u45,
};

// ============================================================================
// Vhost-User Memory
// ============================================================================

pub const VhostUserMemoryRegion = struct {
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    mmap_offset: u64,
};

pub const VhostUserMemory = struct {
    nregions: u32,
    _padding: u32,
    regions: [8]VhostUserMemoryRegion,   // VHOST_MEMORY_MAX_NREGIONS
};

pub const VhostUserSingleMemRegion = struct {
    _padding: u64,
    region: VhostUserMemoryRegion,
};

// ============================================================================
// Vhost-User Vring
// ============================================================================

pub const VhostUserVringAddr = struct {
    index: u32,
    flags: VhostVringAddrFlags,
    desc_user_addr: u64,
    used_user_addr: u64,
    avail_user_addr: u64,
    log_guest_addr: u64,
};

pub const VhostVringAddrFlags = packed struct(u32) {
    log_all: bool,
    _reserved: u31,
};

pub const VhostUserVringState = struct {
    index: u32,
    num: u32,
};

// ============================================================================
// Vhost-User Config
// ============================================================================

pub const VhostUserConfig = struct {
    offset: u32,
    size: u32,
    flags: VhostUserConfigFlags,
    region: [256]u8,     // Config space data
};

pub const VhostUserConfigFlags = packed struct(u32) {
    writable: bool,
    migration: bool,
    _reserved: u30,
};

// ============================================================================
// Vhost-User Inflight
// ============================================================================

pub const VhostUserInflight = struct {
    mmap_size: u64,
    mmap_offset: u64,
    num_queues: u16,
    queue_size: u16,
};

pub const VhostUserInflightDesc = struct {
    inflight: u8,       // Currently in-flight
    _padding: [3]u8,
    next: u16,
    counter: u64,
};

pub const VhostUserInflightRegion = struct {
    features: u64,
    version: u16,
    desc_num: u16,
    last_batch_head: u16,
    used_idx: u16,
    desc: [1024]VhostUserInflightDesc,
};

// ============================================================================
// Vhost Backend
// ============================================================================

pub const VhostBackendType = enum(u8) {
    Net = 0,
    Blk = 1,
    Scsi = 2,
    Fs = 3,
    Crypto = 4,
    Gpu = 5,
    Input = 6,
    Vsock = 7,
    I2c = 8,
    Snd = 9,
    Gpio = 10,
    Rng = 11,
    Can = 12,
    Pmem = 13,
};

pub const VhostBackendOps = struct {
    init: ?*const fn (backend: *VhostBackend) callconv(.C) i32,
    cleanup: ?*const fn (backend: *VhostBackend) callconv(.C) void,
    set_features: ?*const fn (backend: *VhostBackend, features: u64) callconv(.C) i32,
    get_features: ?*const fn (backend: *VhostBackend) callconv(.C) u64,
    get_protocol_features: ?*const fn (backend: *VhostBackend) callconv(.C) u64,
    set_protocol_features: ?*const fn (backend: *VhostBackend, features: u64) callconv(.C) i32,
    get_config: ?*const fn (backend: *VhostBackend, config: *VhostUserConfig) callconv(.C) i32,
    set_config: ?*const fn (backend: *VhostBackend, config: *const VhostUserConfig) callconv(.C) i32,
    start: ?*const fn (backend: *VhostBackend) callconv(.C) i32,
    stop: ?*const fn (backend: *VhostBackend) callconv(.C) i32,
    queue_setup: ?*const fn (backend: *VhostBackend, idx: u32, num: u32) callconv(.C) i32,
    queue_cleanup: ?*const fn (backend: *VhostBackend, idx: u32) callconv(.C) void,
    queue_kick: ?*const fn (backend: *VhostBackend, idx: u32) callconv(.C) i32,
};

pub const VhostBackend = struct {
    backend_type: VhostBackendType,
    ops: ?*const VhostBackendOps,
    features: u64,
    protocol_features: VhostUserProtocolFeatures,
    num_queues: u32,
    max_queues: u32,
    vqs: [256]VhostVirtqueue,
    mem: VhostUserMemory,
    socket_fd: i32,
    backend_fd: i32,
    log_fd: i32,
    running: bool,
    owner: ?*anyopaque,
    dev: ?*anyopaque,
    priv_data: ?*anyopaque,
};

pub const VhostVirtqueue = struct {
    desc_addr: u64,
    avail_addr: u64,
    used_addr: u64,
    num: u32,
    last_avail_idx: u16,
    last_used_idx: u16,
    avail_wrap_counter: bool,
    used_wrap_counter: bool,
    enabled: bool,
    started: bool,
    kick_fd: i32,
    call_fd: i32,
    err_fd: i32,
    signalled_used: u16,
    signalled_used_valid: bool,
    busyloop_timeout: u64,
};

// ============================================================================
// Virtio-FS
// ============================================================================

pub const VirtioFsConfig = struct {
    tag: [36]u8,      // Filesystem name tag
    num_request_queues: u32,
    notify_buf_size: u32,
};

pub const VirtioFsState = enum(u8) {
    Initializing = 0,
    Ready = 1,
    Suspended = 2,
    Error = 3,
};

pub const VirtioFs = struct {
    config: VirtioFsConfig,
    state: VirtioFsState,
    vqs: [128]VhostVirtqueue,  // N request queues + hiprio queue
    num_queues: u32,
    dax_dev: ?*VirtioFsDax,
    conn: ?*FuseConnection,
    mount_point: [256]u8,
    options: VirtioFsMountOpts,
    stats: VirtioFsStats,
};

pub const VirtioFsDax = struct {
    enabled: bool,
    addr: u64,         // DAX window base address
    length: u64,       // DAX window length
    pgoff: u64,
    nr_free_ranges: u32,
    nr_busy_ranges: u32,
    inode_to_range: ?*anyopaque,  // Inode-to-DAX-range mapping
};

pub const VirtioFsMountOpts = struct {
    dax: VirtioFsDaxMode,
    max_read: u32,
    max_write: u32,
    max_pages_per_req: u32,
    writeback: bool,
    no_open: bool,
    no_opendir: bool,
    no_readdir: bool,
    posix_acl: bool,
    no_kill_suid: bool,
};

pub const VirtioFsDaxMode = enum(u8) {
    Never = 0,
    Always = 1,
    Inode = 2,    // Per-inode DAX
};

pub const VirtioFsStats = struct {
    requests_total: u64,
    requests_hiprio: u64,
    bytes_read: u64,
    bytes_written: u64,
    dax_mappings: u64,
    dax_evictions: u64,
    cache_hits: u64,
    cache_misses: u64,
};

// ============================================================================
// FUSE Connection for virtio-fs
// ============================================================================

pub const FuseConnection = struct {
    initialized: bool,
    connected: bool,
    blocked: bool,
    aborted: bool,
    conn_error: bool,
    minor: u32,
    max_read: u32,
    max_write: u32,
    max_pages: u16,
    max_background: u16,
    congestion_threshold: u16,
    num_background: u32,
    active_background: u32,
    no_lock: bool,
    no_access: bool,
    no_create: bool,
    no_flock: bool,
    no_open: bool,
    no_opendir: bool,
    no_fsync: bool,
    no_fsyncdir: bool,
    no_flush: bool,
    no_setxattr: bool,
    no_getxattr: bool,
    no_listxattr: bool,
    no_removexattr: bool,
    no_readdir: bool,
    no_readdirplus: bool,
    no_lseek: bool,
    no_copy_file_range: bool,
    no_fallocate: bool,
    no_rename2: bool,
    writeback_cache: bool,
    parallel_dirops: bool,
    handle_killpriv: bool,
    no_handle_killpriv_v2: bool,
    cache_symlinks: bool,
    explicit_inval_data: bool,
    time_gran: u32,
    default_permissions: bool,
    allow_other: bool,
    auto_submounts: bool,
};

pub const FuseOpcode = enum(u32) {
    FUSE_LOOKUP = 1,
    FUSE_FORGET = 2,
    FUSE_GETATTR = 3,
    FUSE_SETATTR = 4,
    FUSE_READLINK = 5,
    FUSE_SYMLINK = 6,
    FUSE_MKNOD = 8,
    FUSE_MKDIR = 9,
    FUSE_UNLINK = 10,
    FUSE_RMDIR = 11,
    FUSE_RENAME = 12,
    FUSE_LINK = 13,
    FUSE_OPEN = 14,
    FUSE_READ = 15,
    FUSE_WRITE = 16,
    FUSE_STATFS = 17,
    FUSE_RELEASE = 18,
    FUSE_FSYNC = 20,
    FUSE_SETXATTR = 21,
    FUSE_GETXATTR = 22,
    FUSE_LISTXATTR = 23,
    FUSE_REMOVEXATTR = 24,
    FUSE_FLUSH = 25,
    FUSE_INIT = 26,
    FUSE_OPENDIR = 27,
    FUSE_READDIR = 28,
    FUSE_RELEASEDIR = 29,
    FUSE_FSYNCDIR = 30,
    FUSE_GETLK = 31,
    FUSE_SETLK = 32,
    FUSE_SETLKW = 33,
    FUSE_ACCESS = 34,
    FUSE_CREATE = 35,
    FUSE_INTERRUPT = 36,
    FUSE_BMAP = 37,
    FUSE_DESTROY = 38,
    FUSE_IOCTL = 39,
    FUSE_POLL = 40,
    FUSE_NOTIFY_REPLY = 41,
    FUSE_BATCH_FORGET = 42,
    FUSE_FALLOCATE = 43,
    FUSE_READDIRPLUS = 44,
    FUSE_RENAME2 = 45,
    FUSE_LSEEK = 46,
    FUSE_COPY_FILE_RANGE = 47,
    FUSE_SETUPMAPPING = 48,
    FUSE_REMOVEMAPPING = 49,
    FUSE_SYNCFS = 50,
    FUSE_TMPFILE = 51,
    FUSE_STATX = 52,
};

pub const FuseInHeader = packed struct {
    len: u32,
    opcode: u32,
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    total_extlen: u16,
    _padding: u16,
};

pub const FuseOutHeader = packed struct {
    len: u32,
    err: i32,
    unique: u64,
};

pub const FuseInitIn = packed struct {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
    flags2: u32,
    unused: [11]u32,
};

pub const FuseInitOut = packed struct {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
    max_background: u16,
    congestion_threshold: u16,
    max_write: u32,
    time_gran: u32,
    max_pages: u16,
    map_alignment: u16,
    flags2: u32,
    max_stack_depth: u32,
    unused: [6]u32,
};

// ============================================================================
// Vhost-net
// ============================================================================

pub const VhostNet = struct {
    dev: VhostBackend,
    vqs: [2]VhostNetVirtqueue,   // RX + TX
    poll: [2]VhostPoll,
    page_frag: u64,
    refcnt_bias: u32,
    tx_packets: u64,
    tx_bytes: u64,
    tx_zcopy_err: u64,
    rx_packets: u64,
    rx_bytes: u64,
};

pub const VhostNetVirtqueue = struct {
    vq: VhostVirtqueue,
    sock: ?*anyopaque,
    rx_ring: VhostRxRing,
    ubufs: ?*anyopaque,
    upend_idx: i32,
    done_idx: i32,
    batched_xdp: u32,
    xdp: [64]?*anyopaque,
};

pub const VhostRxRing = struct {
    bufs_num: u32,
    outstanding: u32,
};

pub const VhostPoll = struct {
    wqh: ?*anyopaque,
    work: u64,
    mask: u32,
    wqn: u64,
    dev: ?*anyopaque,
};

// ============================================================================
// Vhost-blk
// ============================================================================

pub const VhostBlk = struct {
    dev: VhostBackend,
    vqs: [256]VhostVirtqueue,     // Multi-queue support
    num_queues: u32,
    capacity: u64,                 // Disk size in sectors
    blk_size: u32,
    seg_max: u32,
    num_sectors: u64,
    discard_sector_alignment: u32,
    max_discard_sectors: u32,
    max_discard_seg: u32,
    max_write_zeroes_sectors: u32,
    max_write_zeroes_seg: u32,
    write_zeroes_may_unmap: bool,
    read_only: bool,
    flush: bool,
    discard: bool,
    write_zeroes: bool,
    topology: VhostBlkTopology,
    stats: VhostBlkStats,
};

pub const VhostBlkTopology = struct {
    physical_block_exp: u8,
    alignment_offset: u16,
    min_io_size: u32,
    opt_io_size: u32,
};

pub const VhostBlkStats = struct {
    read_ops: u64,
    write_ops: u64,
    flush_ops: u64,
    discard_ops: u64,
    read_bytes: u64,
    write_bytes: u64,
    read_errors: u64,
    write_errors: u64,
};

// ============================================================================
// Vhost-SCSI
// ============================================================================

pub const VhostScsi = struct {
    dev: VhostBackend,
    vqs: [128]VhostVirtqueue,
    num_queues: u32,
    ctl_vq: VhostVirtqueue,         // Control virtqueue
    evt_vq: VhostVirtqueue,         // Event virtqueue
    targets: [256]?*VhostScsiTarget,
    max_target: u32,
    stats: VhostScsiStats,
};

pub const VhostScsiTarget = struct {
    target_id: u32,
    transport_id: [256]u8,
    naa: [16]u8,
    port_id: [64]u8,
    luns: [256]?*VhostScsiLun,
    max_lun: u32,
};

pub const VhostScsiLun = struct {
    lun_id: u64,
    dev_path: [256]u8,
    read_only: bool,
    thin_provisioning: bool,
    block_size: u32,
    num_blocks: u64,
};

pub const VhostScsiStats = struct {
    cmd_completed: u64,
    cmd_aborted: u64,
    cmd_failed: u64,
    read_bytes: u64,
    write_bytes: u64,
    tmf_completed: u64,
};

// ============================================================================
// Manager
// ============================================================================

pub const VhostVirtioFsManager = struct {
    backends: [32]?*VhostBackend,
    backend_count: u32,
    virtiofs_instances: [8]?*VirtioFs,
    virtiofs_count: u32,
    total_requests: u64,
    total_bytes_transferred: u64,
    initialized: bool,

    pub fn init() VhostVirtioFsManager {
        return .{
            .backends = [_]?*VhostBackend{null} ** 32,
            .backend_count = 0,
            .virtiofs_instances = [_]?*VirtioFs{null} ** 8,
            .virtiofs_count = 0,
            .total_requests = 0,
            .total_bytes_transferred = 0,
            .initialized = true,
        };
    }
};
