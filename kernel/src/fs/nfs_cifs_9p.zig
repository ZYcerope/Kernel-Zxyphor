// SPDX-License-Identifier: MIT
// Zxyphor Kernel - NFS Client, CIFS/SMB Client, 9P Filesystem,
// Distributed File System Fundamentals
// More advanced than Linux 2026 network filesystem stack

const std = @import("std");

// ============================================================================
// NFS (Network File System) Client
// ============================================================================

pub const NfsVersion = enum(u8) {
    v2 = 2,
    v3 = 3,
    v4_0 = 40,
    v4_1 = 41,
    v4_2 = 42,
};

pub const NfsTransport = enum(u8) {
    tcp = 0,
    udp = 1,
    rdma = 2,
};

pub const RpcAuthFlavor = enum(u32) {
    auth_null = 0,
    auth_unix = 1,
    auth_short = 2,
    auth_des = 3,
    rpcsec_gss_krb5 = 390003,
    rpcsec_gss_krb5i = 390004,
    rpcsec_gss_krb5p = 390005,
};

pub const NfsMountOptions = struct {
    version: NfsVersion = .v4_2,
    transport: NfsTransport = .tcp,
    auth: RpcAuthFlavor = .rpcsec_gss_krb5p,
    // Server
    server_addr: [64]u8 = [_]u8{0} ** 64,
    server_port: u16 = 2049,
    export_path: [256]u8 = [_]u8{0} ** 256,
    // Options
    rsize: u32 = 1048576,        // Read size
    wsize: u32 = 1048576,        // Write size
    timeo: u32 = 600,            // Timeout (1/10 sec)
    retrans: u32 = 2,
    acregmin: u32 = 3,           // Attribute cache min (sec)
    acregmax: u32 = 60,
    acdirmin: u32 = 30,
    acdirmax: u32 = 60,
    // Flags
    hard: bool = true,
    intr: bool = false,
    noac: bool = false,
    nocto: bool = false,          // No close-to-open consistency
    noatime: bool = false,
    sec_label: bool = false,      // Security labels
    migration: bool = false,
    // NFSv4+ specific
    clientid: u64 = 0,
    session_id: [16]u8 = [_]u8{0} ** 16,
    // Delegation
    delegations_enabled: bool = true,
    // pNFS (Parallel NFS)
    pnfs_layout_type: PnfsLayoutType = .none,
};

pub const PnfsLayoutType = enum(u32) {
    none = 0,
    nfsv4_1_files = 1,
    osd2_objects = 2,
    block_volume = 3,
    flexfiles = 4,
    scsi = 5,
};

pub const NfsFileHandle = struct {
    size: u8 = 0,
    data: [128]u8 = [_]u8{0} ** 128,
};

pub const NfsFattr = struct {
    valid: u32 = 0,
    type_: NfsFileType = .regular,
    mode: u32 = 0,
    nlink: u32 = 0,
    uid: u32 = 0,
    gid: u32 = 0,
    rdev: u64 = 0,
    size: u64 = 0,
    used: u64 = 0,
    fsid: u64 = 0,
    fileid: u64 = 0,
    atime_sec: i64 = 0,
    atime_nsec: u32 = 0,
    mtime_sec: i64 = 0,
    mtime_nsec: u32 = 0,
    ctime_sec: i64 = 0,
    ctime_nsec: u32 = 0,
    change_attr: u64 = 0,
    // NFSv4
    owner: [64]u8 = [_]u8{0} ** 64,
    group: [64]u8 = [_]u8{0} ** 64,
    mounted_on_fileid: u64 = 0,
    // NFSv4.2
    space_used: u64 = 0,
};

pub const NfsFileType = enum(u8) {
    regular = 1,
    directory = 2,
    blk = 3,
    chr = 4,
    lnk = 5,
    sock = 6,
    fifo = 7,
    attrdir = 8,
    namedattr = 9,
};

pub const NfsDelegationType = enum(u8) {
    none = 0,
    read = 1,
    write = 2,
};

pub const NfsDelegation = struct {
    dtype: NfsDelegationType = .none,
    stateid: [16]u8 = [_]u8{0} ** 16,
    flags: u32 = 0,
    // Recall
    recalled: bool = false,
    returning: bool = false,
};

// NFSv4 state
pub const NfsOpenState = struct {
    open_stateid: [16]u8 = [_]u8{0} ** 16,
    lock_stateid: [16]u8 = [_]u8{0} ** 16,
    access: u32 = 0,
    deny: u32 = 0,
    n_rdonly: u32 = 0,
    n_wronly: u32 = 0,
    n_rdwr: u32 = 0,
};

pub const NfsClientStats = struct {
    total_reads: u64 = 0,
    total_writes: u64 = 0,
    total_commits: u64 = 0,
    total_read_bytes: u64 = 0,
    total_write_bytes: u64 = 0,
    read_latency_sum_ns: u64 = 0,
    write_latency_sum_ns: u64 = 0,
    // RPC
    rpc_calls: u64 = 0,
    rpc_retrans: u64 = 0,
    rpc_timeouts: u64 = 0,
    rpc_auth_refreshes: u64 = 0,
    // pNFS
    pnfs_reads: u64 = 0,
    pnfs_writes: u64 = 0,
    pnfs_not_supported: u64 = 0,
    // Delegations
    delegations_granted: u64 = 0,
    delegations_recalled: u64 = 0,
    delegations_returned: u64 = 0,
};

// ============================================================================
// CIFS/SMB Client
// ============================================================================

pub const SmbDialect = enum(u16) {
    smb_1_0 = 0x0100,
    smb_2_0_2 = 0x0202,
    smb_2_1 = 0x0210,
    smb_3_0 = 0x0300,
    smb_3_0_2 = 0x0302,
    smb_3_1_1 = 0x0311,
};

pub const SmbSecurityMode = packed struct {
    signing_enabled: bool = false,
    signing_required: bool = false,
    encrypt_data: bool = false,
    encryption_required: bool = false,
    _padding: u4 = 0,
};

pub const SmbShareType = enum(u8) {
    disk = 0x01,
    pipe = 0x02,
    print = 0x03,
};

pub const SmbShareCap = packed struct {
    dfs: bool = false,
    continuous_availability: bool = false,
    scaleout: bool = false,
    cluster: bool = false,
    asymmetric: bool = false,
    redirect_to_owner: bool = false,
    _padding: u2 = 0,
};

pub const CifsMountOptions = struct {
    // Server
    server: [256]u8 = [_]u8{0} ** 256,
    share: [256]u8 = [_]u8{0} ** 256,
    port: u16 = 445,
    // Auth
    username: [64]u8 = [_]u8{0} ** 64,
    domain: [64]u8 = [_]u8{0} ** 64,
    security: CifsSecurityType = .krb5,
    // Dialect
    dialect: SmbDialect = .smb_3_1_1,
    // Options
    rsize: u32 = 4194304,
    wsize: u32 = 4194304,
    actimeo: u32 = 1,
    // Flags
    multichannel: bool = true,
    max_channels: u8 = 4,
    seal: bool = false,        // Encryption
    sign: bool = true,         // Signing
    resilientfh: bool = true,  // Resilient file handles
    persistent: bool = false,  // Persistent file handles
    nosharesock: bool = false,
    cache: CifsCacheMode = .strict,
    // SMB Direct (RDMA)
    rdma: bool = false,
    // Compression
    compress: bool = false,
    compress_algo: SmbCompressAlgo = .none,
    // Witness
    witness: bool = false,
};

pub const CifsSecurityType = enum(u8) {
    ntlmv2 = 0,
    krb5 = 1,
    krb5i = 2,
    krb5p = 3,
    ntlmssp = 4,
};

pub const CifsCacheMode = enum(u8) {
    none = 0,
    strict = 1,
    loose = 2,
    single_client = 3,
    ro = 4,
};

pub const SmbCompressAlgo = enum(u16) {
    none = 0x0000,
    lznt1 = 0x0001,
    lz77 = 0x0002,
    lz77_huffman = 0x0003,
    pattern_v1 = 0x0004,
};

pub const CifsOplockLevel = enum(u8) {
    none = 0x00,
    level_ii = 0x01,
    exclusive = 0x08,
    batch = 0x09,
    smb2_read_handle = 0x11,
    smb2_rwh = 0x19,            // Read-Write-Handle lease
};

pub const SmbSessionInfo = struct {
    session_id: u64 = 0,
    dialect: SmbDialect = .smb_3_1_1,
    security_mode: SmbSecurityMode = .{},
    // Signing
    signing_key: [16]u8 = [_]u8{0} ** 16,
    // Encryption
    encryption_key: [16]u8 = [_]u8{0} ** 16,
    decryption_key: [16]u8 = [_]u8{0} ** 16,
    cipher_type: SmbCipherType = .aes_128_gcm,
    // Multi-channel
    nr_channels: u8 = 1,
    // Preauth integrity
    preauth_hash: [64]u8 = [_]u8{0} ** 64,
};

pub const SmbCipherType = enum(u16) {
    aes_128_ccm = 0x0001,
    aes_128_gcm = 0x0002,
    aes_256_ccm = 0x0003,
    aes_256_gcm = 0x0004,
};

pub const CifsClientStats = struct {
    total_reads: u64 = 0,
    total_writes: u64 = 0,
    total_read_bytes: u64 = 0,
    total_write_bytes: u64 = 0,
    smb_requests_sent: u64 = 0,
    smb_responses_received: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    // Errors
    total_retries: u64 = 0,
    session_reconnects: u64 = 0,
    tcon_reconnects: u64 = 0,
    // Cache
    cache_hits: u64 = 0,
    cache_misses: u64 = 0,
    // Locks
    total_locks: u64 = 0,
    total_lock_fails: u64 = 0,
    // Oplocks/Leases
    oplocks_granted: u64 = 0,
    oplocks_broken: u64 = 0,
};

// ============================================================================
// 9P Filesystem (Plan 9)
// ============================================================================

pub const P9Version = enum(u8) {
    p9_2000 = 0,
    p9_2000_u = 1,      // Unix extensions
    p9_2000_L = 2,      // Linux extensions
};

pub const P9Transport = enum(u8) {
    tcp = 0,
    virtio = 1,
    rdma = 2,
    fd = 3,
};

pub const P9MsgType = enum(u8) {
    Tlerror = 6,
    Rlerror = 7,
    Tstatfs = 8,
    Rstatfs = 9,
    Tlopen = 12,
    Rlopen = 13,
    Tlcreate = 14,
    Rlcreate = 15,
    Tsymlink = 16,
    Rsymlink = 17,
    Tmknod = 18,
    Rmknod = 19,
    Trename = 20,
    Rrename = 21,
    Treadlink = 22,
    Rreadlink = 23,
    Tgetattr = 24,
    Rgetattr = 25,
    Tsetattr = 26,
    Rsetattr = 27,
    Txattrwalk = 30,
    Rxattrwalk = 31,
    Txattrcreate = 32,
    Rxattrcreate = 33,
    Treaddir = 40,
    Rreaddir = 41,
    Tfsync = 50,
    Rfsync = 51,
    Tlock = 52,
    Rlock = 53,
    Tgetlock = 54,
    Rgetlock = 55,
    Tlink = 70,
    Rlink = 71,
    Tmkdir = 72,
    Rmkdir = 73,
    Trenameat = 74,
    Rrenameat = 75,
    Tunlinkat = 76,
    Runlinkat = 77,
    Tversion = 100,
    Rversion = 101,
    Tauth = 102,
    Rauth = 103,
    Tattach = 104,
    Rattach = 105,
    Tflush = 108,
    Rflush = 109,
    Twalk = 110,
    Rwalk = 111,
    Tread = 116,
    Rread = 117,
    Twrite = 118,
    Rwrite = 119,
    Tclunk = 120,
    Rclunk = 121,
    Tremove = 122,
    Rremove = 123,
};

pub const P9CacheMode = enum(u8) {
    none = 0,
    loose = 1,
    fscache = 2,
    mmap = 3,
};

pub const P9MountOptions = struct {
    version: P9Version = .p9_2000_L,
    transport: P9Transport = .virtio,
    msize: u32 = 524288,        // Max message size
    cache: P9CacheMode = .fscache,
    aname: [128]u8 = [_]u8{0} ** 128,  // Attach name
    uname: [32]u8 = [_]u8{0} ** 32,
    access: P9AccessMode = .user,
    dfltuid: u32 = 65534,
    dfltgid: u32 = 65534,
    // Flags
    nodevmap: bool = false,
    posixacl: bool = false,
};

pub const P9AccessMode = enum(u8) {
    user = 0,
    any = 1,
    client = 2,
    single = 3,
};

// ============================================================================
// Distributed FS Coordination
// ============================================================================

pub const DfsCoordType = enum(u8) {
    centralized = 0,
    distributed_hash = 1,
    raft_consensus = 2,
    paxos = 3,
    // Zxyphor
    zxy_adaptive = 10,
};

pub const DfsReplicaPolicy = enum(u8) {
    none = 0,
    sync_2 = 1,
    sync_3 = 2,
    async_2 = 3,
    async_3 = 4,
    erasure_coded = 5,
    // Zxyphor
    zxy_adaptive = 10,
};

pub const DfsConsistency = enum(u8) {
    eventual = 0,
    strong = 1,
    causal = 2,
    sequential = 3,
    linearizable = 4,
    // Zxyphor
    zxy_bounded_staleness = 10,
};

pub const DfsNodeInfo = struct {
    node_id: u64 = 0,
    addr: [64]u8 = [_]u8{0} ** 64,
    port: u16 = 0,
    state: DfsNodeState = .unknown,
    role: DfsNodeRole = .follower,
    // Health
    last_heartbeat_ns: u64 = 0,
    latency_avg_us: u32 = 0,
    // Capacity
    total_space: u64 = 0,
    used_space: u64 = 0,
};

pub const DfsNodeState = enum(u8) {
    unknown = 0,
    joining = 1,
    active = 2,
    decommissioning = 3,
    dead = 4,
};

pub const DfsNodeRole = enum(u8) {
    leader = 0,
    follower = 1,
    learner = 2,
    observer = 3,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const NetFsSubsystem = struct {
    // NFS
    nr_nfs_mounts: u32 = 0,
    nfs_stats: NfsClientStats = .{},
    // CIFS
    nr_cifs_mounts: u32 = 0,
    cifs_stats: CifsClientStats = .{},
    // 9P
    nr_9p_mounts: u32 = 0,
    total_9p_requests: u64 = 0,
    // DFS
    nr_dfs_nodes: u32 = 0,
    dfs_coordination: DfsCoordType = .centralized,
    dfs_replica_policy: DfsReplicaPolicy = .sync_3,
    dfs_consistency: DfsConsistency = .linearizable,
    // Zxyphor
    zxy_auto_failover: bool = false,
    initialized: bool = false,
};
