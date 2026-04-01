// SPDX-License-Identifier: MIT
// Zxyphor Kernel - POSIX Message Queues, SysV Semaphores, SysV Shared Memory,
// SysV Message Queues, IPC Namespace, Key Management
// More advanced than Linux 2026 IPC subsystem

const std = @import("std");

// ============================================================================
// IPC Permissions (Common to SysV IPC)
// ============================================================================

/// IPC permission structure
pub const IpcPerm = struct {
    key: i32,
    uid: u32,
    gid: u32,
    cuid: u32,    // Creator uid
    cgid: u32,    // Creator gid
    mode: u16,
    seq: u16,     // Sequence number
};

/// IPC command types
pub const IPC_CREAT: i32 = 0o1000;
pub const IPC_EXCL: i32 = 0o2000;
pub const IPC_NOWAIT: i32 = 0o4000;
pub const IPC_PRIVATE: i32 = 0;
pub const IPC_RMID: i32 = 0;
pub const IPC_SET: i32 = 1;
pub const IPC_STAT: i32 = 2;
pub const IPC_INFO: i32 = 3;

// ============================================================================
// POSIX Message Queues
// ============================================================================

/// POSIX MQ attributes
pub const MqAttr = struct {
    mq_flags: i64,     // 0 or O_NONBLOCK
    mq_maxmsg: i64,    // Max messages in queue
    mq_msgsize: i64,   // Max message size (bytes)
    mq_curmsgs: i64,   // Current messages in queue
};

/// POSIX MQ instance
pub const PosixMqueue = struct {
    name: [256]u8,
    name_len: u16,
    // Attributes
    attr: MqAttr,
    // Permissions
    uid: u32,
    gid: u32,
    mode: u16,
    // Notification
    notify_type: MqNotifyType,
    notify_signo: i32,
    notify_pid: i32,
    // Stats
    total_sent: u64,
    total_received: u64,
    total_sent_bytes: u64,
    total_received_bytes: u64,
    total_timeouts: u64,
    total_full_waits: u64,
    total_empty_waits: u64,
    // Timestamps
    last_send_ns: u64,
    last_receive_ns: u64,
    create_time_ns: u64,
};

/// MQ notification type
pub const MqNotifyType = enum(u8) {
    none = 0,          // SIGEV_NONE
    signal = 1,        // SIGEV_SIGNAL
    thread = 2,        // SIGEV_THREAD
};

/// MQ message priority
pub const MQ_PRIO_MAX: u32 = 32768;

/// POSIX MQ system limits
pub const MqLimits = struct {
    queues_max: u32,       // /proc/sys/fs/mqueue/queues_max
    msg_max: u32,          // /proc/sys/fs/mqueue/msg_max
    msgsize_max: u32,      // /proc/sys/fs/mqueue/msgsize_max
    msg_default: u32,      // /proc/sys/fs/mqueue/msg_default
    msgsize_default: u32,  // /proc/sys/fs/mqueue/msgsize_default
    // Current usage
    current_queues: u32,
};

// ============================================================================
// SysV Message Queues
// ============================================================================

/// SysV message type
pub const SysvMsgType = struct {
    mtype: i64,         // Message type (must be > 0)
    // mtext follows
};

/// SysV message queue info
pub const MsqidDs = struct {
    msg_perm: IpcPerm,
    msg_stime: i64,      // Last msgsnd time
    msg_rtime: i64,      // Last msgrcv time
    msg_ctime: i64,      // Last change time
    msg_cbytes: u64,     // Current bytes in queue
    msg_qnum: u64,       // Current messages in queue
    msg_qbytes: u64,     // Max bytes in queue
    msg_lspid: i32,      // Last msgsnd PID
    msg_lrpid: i32,      // Last msgrcv PID
};

/// SysV MQ info (IPC_INFO)
pub const MsgInfo = struct {
    msgpool: u32,     // Size of buffer pool in kB
    msgmap: u32,      // Max # of entries in message map
    msgmax: u32,      // Max size of a single message
    msgmnb: u32,      // Max bytes per queue default
    msgmni: u32,      // Max # of message queue identifiers
    msgssz: u32,      // Message segment size
    msgtql: u32,      // Max # of messages = msgmni * msgmnb / msgmax
    msgseg: u16,      // Max # of message segments
};

/// SysV MQ commands
pub const MSG_STAT: i32 = 11;
pub const MSG_INFO: i32 = 12;
pub const MSG_STAT_ANY: i32 = 13;
pub const MSG_NOERROR: i32 = 0o10000; // Truncate rather than error
pub const MSG_EXCEPT: i32 = 0o20000;  // Receive any except mtype
pub const MSG_COPY: i32 = 0o40000;    // Copy (not remove) from queue

// ============================================================================
// SysV Semaphores
// ============================================================================

/// Semaphore operation
pub const SemBuf = struct {
    sem_num: u16,     // Semaphore number
    sem_op: i16,      // Semaphore operation
    sem_flg: i16,     // Operation flags
};

/// Semaphore operation flags
pub const SEM_UNDO: i16 = 0x1000;
pub const SEM_GETVAL: i32 = 12;
pub const SEM_GETPID: i32 = 11;
pub const SEM_GETNCNT: i32 = 14;
pub const SEM_GETZCNT: i32 = 15;
pub const SEM_GETALL: i32 = 13;
pub const SEM_SETVAL: i32 = 16;
pub const SEM_SETALL: i32 = 17;
pub const SEM_STAT: i32 = 18;
pub const SEM_INFO: i32 = 19;
pub const SEM_STAT_ANY: i32 = 20;

/// Semaphore set info
pub const SemidDs = struct {
    sem_perm: IpcPerm,
    sem_otime: i64,     // Last semop time
    sem_ctime: i64,     // Last change time
    sem_nsems: u32,     // Number of semaphores in set
};

/// Semaphore info
pub const SemInfo = struct {
    semmap: u32,
    semmni: u32,     // Max # of semaphore sets
    semmns: u32,     // Max # of semaphores system-wide
    semmnu: u32,     // Max # of undo structures
    semmsl: u32,     // Max semaphores per set
    semopm: u32,     // Max operations per semop
    semume: u32,     // Max undo entries per process
    semusz: u32,     // Size of struct sem_undo
    semvmx: u32,     // Max semaphore value
    semaem: u32,     // Max value for adjustment
};

/// Per-semaphore info
pub const SemValue = struct {
    value: u32,
    sempid: i32,        // PID of last semop
    semncnt: u32,       // # waiting for value increase
    semzcnt: u32,       // # waiting for value = 0
};

// ============================================================================
// SysV Shared Memory
// ============================================================================

/// Shared memory flags
pub const SHM_RDONLY: i32 = 0o10000;
pub const SHM_RND: i32 = 0o20000;
pub const SHM_REMAP: i32 = 0o40000;
pub const SHM_EXEC: i32 = 0o100000;
pub const SHM_HUGETLB: i32 = 0o4000;
pub const SHM_NORESERVE: i32 = 0o10000;

/// Shared memory segment info
pub const ShmidDs = struct {
    shm_perm: IpcPerm,
    shm_segsz: u64,    // Size in bytes
    shm_atime: i64,    // Last attach time
    shm_dtime: i64,    // Last detach time
    shm_ctime: i64,    // Last change time
    shm_cpid: i32,     // Creator PID
    shm_lpid: i32,     // Last shmat/shmdt PID
    shm_nattch: u32,   // Current attaches
};

/// SysV SHM commands
pub const SHM_STAT: i32 = 13;
pub const SHM_INFO_CMD: i32 = 14;
pub const SHM_STAT_ANY: i32 = 15;
pub const SHM_LOCK: i32 = 11;
pub const SHM_UNLOCK: i32 = 12;

/// SHM info
pub const ShmInfo = struct {
    used_ids: u32,
    shm_tot: u64,      // Total shared memory in pages
    shm_rss: u64,      // Resident shared memory in pages
    shm_swp: u64,      // Swapped shared memory in pages
    swap_attempts: u64,
    swap_successes: u64,
};

/// SHM system limits
pub const ShmLimits = struct {
    shmmax: u64,     // Max segment size
    shmmin: u64,     // Min segment size (always 1)
    shmmni: u32,     // Max # of segments
    shmall: u64,     // Max total shared memory in pages
    shmseg: u32,     // Max # of segments per process
};

// ============================================================================
// IPC Namespace
// ============================================================================

/// IPC namespace
pub const IpcNamespace = struct {
    id: u64,
    // SysV IPC IDs
    msg_ids_in_use: u32,
    sem_ids_in_use: u32,
    shm_ids_in_use: u32,
    // Limits
    msg_ctlmax: u32,
    msg_ctlmnb: u32,
    msg_ctlmni: u32,
    sem_ctls: SemInfo,
    shm_ctlmax: u64,
    shm_ctlall: u64,
    shm_ctlmni: u32,
    shm_rmid_forced: bool,
    // POSIX MQ
    mq_queues_count: u32,
    mq_queues_max: u32,
    mq_msg_max: u32,
    mq_msgsize_max: u32,
    // Stats
    total_ipc_creates: u64,
    total_ipc_destroys: u64,
};

// ============================================================================
// Key Management Facility (Keyring)
// ============================================================================

/// Key type
pub const KeyType = enum(u8) {
    keyring = 0,
    user = 1,
    logon = 2,
    big_key = 3,
    encrypted = 4,
    trusted = 5,
    asymmetric = 6,
    dns_resolver = 7,
    rxrpc = 8,
    rxrpc_s = 9,
    ceph = 10,
    pkcs7_test = 11,
    // Zxyphor
    zxy_tpm2 = 50,
    zxy_hwsec = 51,
};

/// Key permissions
pub const KeyPerm = packed struct {
    // Possessor permissions
    poss_view: bool = false,
    poss_read: bool = false,
    poss_write: bool = false,
    poss_search: bool = false,
    poss_link: bool = false,
    poss_setattr: bool = false,
    poss_all: bool = false,
    _pad1: u1 = 0,
    // User permissions
    usr_view: bool = false,
    usr_read: bool = false,
    usr_write: bool = false,
    usr_search: bool = false,
    usr_link: bool = false,
    usr_setattr: bool = false,
    usr_all: bool = false,
    _pad2: u1 = 0,
    // Group permissions
    grp_view: bool = false,
    grp_read: bool = false,
    grp_write: bool = false,
    grp_search: bool = false,
    grp_link: bool = false,
    grp_setattr: bool = false,
    grp_all: bool = false,
    _pad3: u1 = 0,
    // Other permissions
    oth_view: bool = false,
    oth_read: bool = false,
    oth_write: bool = false,
    oth_search: bool = false,
    oth_link: bool = false,
    oth_setattr: bool = false,
    oth_all: bool = false,
    _pad4: u1 = 0,
};

/// Key description
pub const Key = struct {
    serial: i32,        // Key serial number
    key_type: KeyType,
    description: [256]u8,
    description_len: u16,
    // Ownership
    uid: u32,
    gid: u32,
    perm: u32,         // KeyPerm as u32
    // Expiry
    expiry: i64,       // Expiry time (0 = no expiry)
    // Size
    datalen: u32,
    // Flags
    revoked: bool,
    dead: bool,
    instantiated: bool,
    negative: bool,
    // Quota
    quotalen: u32,
    // Link count
    nlink: u32,
};

/// Keyring special IDs
pub const KEY_SPEC_THREAD_KEYRING: i32 = -1;
pub const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
pub const KEY_SPEC_SESSION_KEYRING: i32 = -3;
pub const KEY_SPEC_USER_KEYRING: i32 = -4;
pub const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;
pub const KEY_SPEC_GROUP_KEYRING: i32 = -6;
pub const KEY_SPEC_REQKEY_AUTH_KEY: i32 = -7;

/// KEYCTL commands
pub const KeyctlCmd = enum(u32) {
    get_keyring_id = 0,
    join_session_keyring = 1,
    update = 2,
    revoke = 3,
    chown = 4,
    setperm = 5,
    describe = 6,
    clear = 7,
    link = 8,
    unlink = 9,
    search = 10,
    read = 11,
    instantiate = 12,
    negate = 13,
    set_reqkey_keyring = 14,
    set_timeout = 15,
    assume_authority = 16,
    get_security = 17,
    session_to_parent = 18,
    reject = 19,
    instantiate_iov = 20,
    invalidate = 21,
    get_persistent = 22,
    dh_compute = 23,
    pkey_query = 24,
    pkey_encrypt = 25,
    pkey_decrypt = 26,
    pkey_sign = 27,
    pkey_verify = 28,
    restrict_keyring = 29,
    move_key = 30,
    capabilities = 31,
    watch_key = 32,
};

/// Kernel keyring configuration
pub const KeyringConfig = struct {
    // Limits
    maxkeys: u32,
    maxbytes: u32,
    root_maxkeys: u32,
    root_maxbytes: u32,
    // GC
    gc_delay: u32,
    // Stats
    total_keys: u64,
    total_keyrings: u64,
    total_key_lookups: u64,
    total_key_creates: u64,
    total_key_revokes: u64,
    total_key_expires: u64,
    total_key_gc: u64,
    // Quota
    user_keys: u32,
    user_bytes: u32,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

/// IPC subsystem
pub const IpcSubsystem = struct {
    // POSIX MQ
    mq_limits: MqLimits,
    total_mq_messages_sent: u64,
    total_mq_messages_received: u64,
    // SysV Message Queues
    msgq_in_use: u32,
    total_msgsnd: u64,
    total_msgrcv: u64,
    // SysV Semaphores
    semsets_in_use: u32,
    total_semop: u64,
    total_sem_undo: u64,
    // SysV Shared Memory
    shm_segments_in_use: u32,
    shm_total_bytes: u64,
    total_shmat: u64,
    total_shmdt: u64,
    // Namespaces
    nr_ipc_ns: u32,
    // Keyrings
    keyring: KeyringConfig,
    // Zxyphor
    zxy_fast_ipc: bool,
    zxy_secure_ipc: bool,
    initialized: bool,

    pub fn init() IpcSubsystem {
        return IpcSubsystem{
            .mq_limits = std.mem.zeroes(MqLimits),
            .total_mq_messages_sent = 0,
            .total_mq_messages_received = 0,
            .msgq_in_use = 0,
            .total_msgsnd = 0,
            .total_msgrcv = 0,
            .semsets_in_use = 0,
            .total_semop = 0,
            .total_sem_undo = 0,
            .shm_segments_in_use = 0,
            .shm_total_bytes = 0,
            .total_shmat = 0,
            .total_shmdt = 0,
            .nr_ipc_ns = 1,
            .keyring = std.mem.zeroes(KeyringConfig),
            .zxy_fast_ipc = true,
            .zxy_secure_ipc = true,
            .initialized = false,
        };
    }
};
