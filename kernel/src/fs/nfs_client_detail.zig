// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - NFS Client Detail
// NFSv3, NFSv4.0/4.1/4.2, RPC/RDMA, delegation, state, open/lock, pNFS

const std = @import("std");

// ============================================================================
// NFS Version and Protocol Constants
// ============================================================================

pub const NfsVersion = enum(u8) {
    V2 = 2,
    V3 = 3,
    V40 = 40,
    V41 = 41,
    V42 = 42,
};

pub const NFS_PROG: u32 = 100003;
pub const NFS_PORT: u16 = 2049;
pub const NFS4_MAX_OPS: u32 = 256;
pub const NFS4_MAXNAMLEN: u32 = 255;
pub const NFS4_MAXPATHLEN: u32 = 4096;
pub const NFS4_FHSIZE: u32 = 128;
pub const NFS3_FHSIZE: u32 = 64;

pub const RpcAuthFlavor = enum(u32) {
    AuthNull = 0,
    AuthUnix = 1,       // AUTH_SYS
    AuthShort = 2,
    AuthDes = 3,
    AuthKerb = 4,
    RpcsecGss = 6,
};

pub const RpcsecGssService = enum(u32) {
    None = 0,
    Integrity = 1,      // krb5i
    Privacy = 2,        // krb5p
};

// ============================================================================
// NFS File Handle
// ============================================================================

pub const NfsFh = struct {
    size: u16,
    data: [NFS4_FHSIZE]u8,
};

pub const NfsFattr = struct {
    valid: NfsAttrValid,
    fileid: u64,
    size: u64,
    allocated_size: u64,
    nlinks: u32,
    uid: u32,
    gid: u32,
    mode: u32,
    atime: NfsTime,
    mtime: NfsTime,
    ctime: NfsTime,
    change_attr: u64,
    rdev: u64,
    fsid: NfsFsid,
    fs_locations: u64,    // nfs4_fs_locations *
    security_label: [256]u8,
    label_len: u16,
};

pub const NfsAttrValid = packed struct(u64) {
    type_valid: bool = false,
    mode_valid: bool = false,
    nlink_valid: bool = false,
    owner_valid: bool = false,
    group_valid: bool = false,
    size_valid: bool = false,
    atime_valid: bool = false,
    mtime_valid: bool = false,
    ctime_valid: bool = false,
    fileid_valid: bool = false,
    change_valid: bool = false,
    space_used_valid: bool = false,
    fs_locations_valid: bool = false,
    security_label_valid: bool = false,
    _pad: u50 = 0,
};

pub const NfsTime = struct {
    seconds: i64,
    nseconds: u32,
};

pub const NfsFsid = struct {
    major: u64,
    minor: u64,
};

// ============================================================================
// NFSv3 Specific
// ============================================================================

pub const Nfs3Status = enum(u32) {
    Ok = 0,
    Perm = 1,
    Noent = 2,
    Io = 5,
    Nxio = 6,
    Acces = 13,
    Exist = 17,
    Xdev = 18,
    Nodev = 19,
    Notdir = 20,
    Isdir = 21,
    Inval = 22,
    Fbig = 27,
    Nospc = 28,
    Rofs = 30,
    Mlink = 31,
    Nametoolong = 63,
    Notempty = 66,
    Dquot = 69,
    Stale = 70,
    Remote = 71,
    Badhandle = 10001,
    NotSync = 10002,
    BadCookie = 10003,
    NotSupp = 10004,
    TooSmall = 10005,
    ServerFault = 10006,
    Badtype = 10007,
    Jukebox = 10008,
};

pub const Nfs3Proc = enum(u32) {
    Null = 0,
    Getattr = 1,
    Setattr = 2,
    Lookup = 3,
    Access = 4,
    Readlink = 5,
    Read = 6,
    Write = 7,
    Create = 8,
    Mkdir = 9,
    Symlink = 10,
    Mknod = 11,
    Remove = 12,
    Rmdir = 13,
    Rename = 14,
    Link = 15,
    Readdir = 16,
    Readdirplus = 17,
    Fsstat = 18,
    Fsinfo = 19,
    Pathconf = 20,
    Commit = 21,
};

// ============================================================================
// NFSv4 Operations
// ============================================================================

pub const Nfs4Op = enum(u32) {
    Access = 3,
    Close = 4,
    Commit = 5,
    Create = 6,
    Delegpurge = 7,
    Delegreturn = 8,
    Getattr = 9,
    Getfh = 10,
    Link = 11,
    Lock = 12,
    Lockt = 13,
    Locku = 14,
    Lookup = 15,
    Lookupp = 16,
    Nverify = 17,
    Open = 18,
    Openattr = 19,
    OpenConfirm = 20,
    OpenDowngrade = 21,
    Putfh = 22,
    Putpubfh = 23,
    Putrootfh = 24,
    Read = 25,
    Readdir = 26,
    Readlink = 27,
    Remove = 28,
    Rename = 29,
    Renew = 30,
    Restorefh = 31,
    Savefh = 32,
    Secinfo = 33,
    Setattr = 34,
    Setclientid = 35,
    SetclientidConfirm = 36,
    Verify = 37,
    Write = 38,
    ReleaseLockowner = 39,
    // NFSv4.1
    BackchannelCtl = 40,
    BindConnToSession = 41,
    ExchangeId = 42,
    CreateSession = 43,
    DestroySession = 44,
    FreeStateid = 45,
    GetDirDelegation = 46,
    Getdeviceinfo = 47,
    Getdevicelist = 48,
    Layoutcommit = 49,
    Layoutget = 50,
    Layoutreturn = 51,
    SecinfoNoName = 52,
    Sequence = 53,
    SetSsv = 54,
    TestStateid = 55,
    WantDelegation = 56,
    DestroyClientid = 57,
    ReclaimComplete = 58,
    // NFSv4.2
    Allocate = 59,
    Copy = 60,
    CopyNotify = 61,
    Deallocate = 62,
    IoAdvise = 63,
    Layouterror = 64,
    Layoutstats = 65,
    OffloadCancel = 66,
    OffloadStatus = 67,
    ReadPlus = 68,
    Seek = 69,
    WriteSame = 70,
    Clone = 71,
    Getxattr = 72,
    Setxattr = 73,
    Listxattrs = 74,
    Removexattr = 75,
};

// ============================================================================
// NFSv4 State
// ============================================================================

pub const Nfs4StateId = struct {
    seqid: u32,
    other: [12]u8,

    pub const ZERO: Nfs4StateId = .{ .seqid = 0, .other = [_]u8{0} ** 12 };
};

pub const Nfs4ClientId = struct {
    verifier: [8]u8,
    id: [1024]u8,
    id_len: u16,
};

pub const Nfs4SessionId = struct {
    data: [16]u8,
};

pub const Nfs4OpenClaim = enum(u32) {
    Null = 0,
    Previous = 1,
    DelegateCur = 2,
    DelegatePrev = 3,
    // NFSv4.1
    FhName = 4,
    DelegateCurFh = 5,
    DelegatePrevFh = 6,
};

pub const Nfs4DelegationType = enum(u32) {
    None = 0,
    Read = 1,
    Write = 2,
    // NFSv4.1
    ReadNamed = 3,
    WriteNamed = 4,
};

pub const Nfs4OpenShare = packed struct(u32) {
    access_read: bool = false,
    access_write: bool = false,
    access_both: bool = false,
    deny_none: bool = false,
    deny_read: bool = false,
    deny_write: bool = false,
    deny_both: bool = false,
    _pad: u25 = 0,
};

pub const Nfs4OpenState = struct {
    stateid: Nfs4StateId,
    lock_stateid: Nfs4StateId,
    share: Nfs4OpenShare,
    delegation: Nfs4DelegationType,
    deleg_stateid: Nfs4StateId,
    change_attr: u64,
    seqid: u32,
    opened: bool,
    flags: OpenStateFlags,
};

pub const OpenStateFlags = packed struct(u32) {
    reclaim: bool = false,
    recovering: bool = false,
    need_close: bool = false,
    may_notify_lock: bool = false,
    _pad: u28 = 0,
};

// ============================================================================
// NFSv4 Lock
// ============================================================================

pub const Nfs4LockType = enum(u32) {
    ReadLt = 1,
    WriteLt = 2,
    ReadwLt = 3,    // blocking
    WritewLt = 4,   // blocking
};

pub const Nfs4Lock = struct {
    lock_type: Nfs4LockType,
    reclaim: bool,
    offset: u64,
    length: u64,
    new_lock_owner: bool,
    open_seqid: u32,
    open_stateid: Nfs4StateId,
    lock_seqid: u32,
    lock_owner: NfsLockOwner,
};

pub const NfsLockOwner = struct {
    clientid: u64,
    owner_id: u64,
};

// ============================================================================
// NFSv4.1 Session
// ============================================================================

pub const Nfs41Session = struct {
    session_id: Nfs4SessionId,
    sequence_id: u32,
    // Channel attributes
    fore_channel: ChannelAttrs,
    back_channel: ChannelAttrs,
    // Slot table
    max_slots: u32,
    target_max_slots: u32,
    slot_table: [128]SlotEntry,
    // Callbacks
    cb_program: u32,
    cb_ident: u32,
    // State
    flags: SessionFlags,
};

pub const ChannelAttrs = struct {
    max_rqst_sz: u32,
    max_resp_sz: u32,
    max_resp_sz_cached: u32,
    max_ops: u32,
    max_reqs: u32,
    rdma_ird: u32,
};

pub const SlotEntry = struct {
    seq_nr: u32,
    seq_nr_last_acked: u32,
    in_use: bool,
    cached_reply: u64,
    cached_reply_len: u32,
};

pub const SessionFlags = packed struct(u32) {
    persist: bool = false,
    back_chan: bool = false,
    rdma: bool = false,
    _pad: u29 = 0,
};

// ============================================================================
// pNFS (Parallel NFS)
// ============================================================================

pub const PnfsLayoutType = enum(u32) {
    NfsLayoutFiles = 1,
    NfsLayoutBlock = 3,
    NfsLayoutObjects = 2,    // deprecated
    NfsLayoutFlexfiles = 4,
    NfsLayoutScsi = 5,
};

pub const PnfsIomode = enum(u32) {
    Read = 1,
    Rw = 2,
    Any = 3,
};

pub const PnfsLayoutSegment = struct {
    layout_type: PnfsLayoutType,
    iomode: PnfsIomode,
    offset: u64,
    length: u64,
    stateid: Nfs4StateId,
    // Device info
    device_id: [16]u8,
    // Stripe info (file layout)
    stripe_unit: u32,
    stripe_count: u32,
    first_stripe_index: u32,
    pattern_offset: u64,
    // Data servers (file layout)
    ds_addrs: [32]NfsDataServer,
    num_ds: u32,
};

pub const NfsDataServer = struct {
    addr: [64]u8,
    addr_len: u16,
    port: u16,
    stateid: Nfs4StateId,
    fh: NfsFh,
    session_id: Nfs4SessionId,
    multipath_index: u32,
};

pub const PnfsLayoutCommit = struct {
    offset: u64,
    length: u64,
    last_write_offset: u64,
    time_modify: NfsTime,
    layoutupdate: [512]u8,
    layoutupdate_len: u32,
};

// ============================================================================
// NFSv4.2 Features
// ============================================================================

pub const Nfs42CopyArgs = struct {
    src_stateid: Nfs4StateId,
    dst_stateid: Nfs4StateId,
    src_offset: u64,
    dst_offset: u64,
    count: u64,
    consecutive: bool,
    synchronous: bool,
    src_fh: NfsFh,
};

pub const Nfs42SeekArgs = struct {
    stateid: Nfs4StateId,
    offset: u64,
    what: SeekWhat,
};

pub const SeekWhat = enum(u32) {
    Data = 0,
    Hole = 1,
};

pub const Nfs42SpaceReserve = struct {
    stateid: Nfs4StateId,
    offset: u64,
    length: u64,
};

// ============================================================================
// RPC Transport
// ============================================================================

pub const RpcTransportType = enum(u8) {
    Tcp = 0,
    Udp = 1,
    Rdma = 2,
    Local = 3,     // AF_LOCAL for NFSd
};

pub const RpcClient = struct {
    transport: RpcTransportType,
    auth_flavor: RpcAuthFlavor,
    gss_service: RpcsecGssService,
    program: u32,
    version: u32,
    max_payload: u32,
    // Connection
    server_addr: [128]u8,
    server_addr_len: u16,
    server_port: u16,
    // Timeouts
    timeout_init: u32,       // initial timeout ms
    timeout_max: u32,        // max timeout ms
    timeout_retries: u32,
    // Statistics
    total_rpc_calls: u64,
    total_rpc_retrans: u64,
    total_auth_refreshes: u64,
    total_timeouts: u64,
    rpc_in_bytes: u64,
    rpc_out_bytes: u64,
};

// ============================================================================
// NFS Mount Options
// ============================================================================

pub const NfsMountOpts = struct {
    version: NfsVersion,
    transport: RpcTransportType,
    auth: RpcAuthFlavor,
    // Sizes
    rsize: u32,              // read size
    wsize: u32,              // write size
    bsize: u32,              // block size
    // Timeouts
    timeo: u32,              // timeout (tenths of seconds)
    retrans: u32,
    acregmin: u32,           // attr cache timeout min (regular files)
    acregmax: u32,
    acdirmin: u32,           // attr cache timeout min (directories)
    acdirmax: u32,
    // Flags
    flags: NfsMountFlags,
    // NFSv4
    clientaddr: [64]u8,
    migration: bool,
    // pNFS
    pnfs_policy: PnfsPolicy,
};

pub const NfsMountFlags = packed struct(u32) {
    soft: bool = false,
    intr: bool = false,       // deprecated
    posix: bool = false,
    nocto: bool = false,
    noac: bool = false,
    tcp: bool = true,
    rdma: bool = false,
    acl: bool = true,
    nordirplus: bool = false,
    noatime: bool = false,
    fscache: bool = false,
    migration: bool = false,
    local_lock_all: bool = false,
    local_lock_flock: bool = false,
    local_lock_posix: bool = false,
    noresvport: bool = false,
    _pad: u16 = 0,
};

pub const PnfsPolicy = enum(u8) {
    Default = 0,
    NotTried = 1,
    Never = 2,
};

// ============================================================================
// NFS Client Stats
// ============================================================================

pub const NfsClientStats = struct {
    // Per-operation counters
    getattr_count: u64,
    setattr_count: u64,
    lookup_count: u64,
    access_count: u64,
    read_count: u64,
    write_count: u64,
    commit_count: u64,
    open_count: u64,
    close_count: u64,
    lock_count: u64,
    readdir_count: u64,
    // Byte counters
    read_bytes: u64,
    write_bytes: u64,
    direct_read_bytes: u64,
    direct_write_bytes: u64,
    // Cache
    attr_cache_hits: u64,
    attr_cache_misses: u64,
    data_cache_hits: u64,
    data_cache_misses: u64,
    // pNFS
    pnfs_read_count: u64,
    pnfs_write_count: u64,
    pnfs_commit_count: u64,
    // Delegation
    deleg_grants: u64,
    deleg_returns: u64,
    deleg_recalls: u64,
    // Errors
    short_reads: u64,
    short_writes: u64,
    server_errors: u64,
    timeouts: u64,
    stale_fh: u64,
    jukebox_delays: u64,
};

pub const NfsClientManager = struct {
    stats: NfsClientStats,
    mounted_servers: u32,
    active_sessions: u32,
    initialized: bool,

    pub fn init() NfsClientManager {
        return .{
            .stats = std.mem.zeroes(NfsClientStats),
            .mounted_servers = 0,
            .active_sessions = 0,
            .initialized = true,
        };
    }
};
