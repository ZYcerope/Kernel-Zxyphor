// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Rust: Filesystem encryption (fscrypt), verity (fsverity),
// io_uring advanced ops, fallocate, file sealing, directory operations,
// inotify/fanotify, file hole management, POSIX file locking
// More advanced than Linux 2026 filesystem features

/// fscrypt policy version
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FscryptPolicyVersion {
    V1 = 1,
    V2 = 2,
}

/// fscrypt encryption mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FscryptMode {
    Aes256Xts = 1,          // Contents: AES-256-XTS
    Aes256Cts = 4,          // Filenames: AES-256-CTS-CBC
    Aes128Cbc = 5,
    Aes128Cts = 6,
    Adiantum = 9,            // For devices without AES hardware
    Aes256Hctr2 = 10,       // HCTR2 (wide-block encryption)
    Sm4Xts = 11,            // SM4-XTS (Chinese standard)
    Sm4Cts = 12,            // SM4-CTS
    // Zxyphor
    ZxyChaCha20 = 20,
    ZxyAes256GcmSiv = 21,
}

/// fscrypt flags
#[derive(Debug, Clone, Copy)]
pub struct FscryptFlags {
    pub direct_key: bool,
    pub iv_ino_lblk_64: bool,
    pub iv_ino_lblk_32: bool,
}

/// fscrypt policy v2
#[derive(Debug, Clone)]
pub struct FscryptPolicyV2 {
    pub version: FscryptPolicyVersion,
    pub contents_encryption_mode: FscryptMode,
    pub filenames_encryption_mode: FscryptMode,
    pub flags: FscryptFlags,
    pub master_key_identifier: [u8; 16],
}

/// fscrypt key specifier
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FscryptKeySpecType {
    Descriptor = 1,
    Identifier = 2,
}

/// fscrypt key status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FscryptKeyStatus {
    Absent = 1,
    Present = 2,
    IncompatiblePolicy = 3,
}

/// fscrypt ioctls
pub const FS_IOC_SET_ENCRYPTION_POLICY: u32 = 0xC0046613;
pub const FS_IOC_GET_ENCRYPTION_POLICY_EX: u32 = 0xC0096616;
pub const FS_IOC_ADD_ENCRYPTION_KEY: u32 = 0xC0506617;
pub const FS_IOC_REMOVE_ENCRYPTION_KEY: u32 = 0xC0406618;
pub const FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS: u32 = 0xC0406619;
pub const FS_IOC_GET_ENCRYPTION_KEY_STATUS: u32 = 0xC040661A;
pub const FS_IOC_GET_ENCRYPTION_NONCE: u32 = 0x8010661B;

// ============================================================================
// fsverity (File-based Verification)
// ============================================================================

/// fsverity hash algorithm
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsVerityHashAlgorithm {
    Sha256 = 1,
    Sha512 = 2,
    // Zxyphor
    ZxyBlake3 = 100,
}

/// fsverity descriptor
#[derive(Debug, Clone)]
pub struct FsVerityDescriptor {
    pub version: u8,           // Always 1
    pub hash_algorithm: FsVerityHashAlgorithm,
    pub log_blocksize: u8,     // log2(block_size), typically 12 (4096)
    pub salt_size: u8,
    pub data_size: u64,
    pub root_hash: [u8; 64],   // Max SHA-512
    pub salt: [u8; 32],
    // Signature
    pub has_builtin_signature: bool,
}

/// fsverity enable args
#[derive(Debug, Clone)]
pub struct FsVerityEnableArg {
    pub version: u32,
    pub hash_algorithm: FsVerityHashAlgorithm,
    pub block_size: u32,
    pub salt_size: u32,
    pub salt_ptr: u64,
    pub sig_size: u32,
    pub sig_ptr: u64,
}

/// fsverity ioctls
pub const FS_IOC_ENABLE_VERITY: u32 = 0x40806685;
pub const FS_IOC_MEASURE_VERITY: u32 = 0xC0046686;
pub const FS_IOC_READ_VERITY_METADATA: u32 = 0xC0286687;

// ============================================================================
// io_uring Advanced Operations
// ============================================================================

/// io_uring submission queue entry opcode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoUringOp {
    Nop = 0,
    Readv = 1,
    Writev = 2,
    Fsync = 3,
    ReadFixed = 4,
    WriteFixed = 5,
    PollAdd = 6,
    PollRemove = 7,
    SyncFileRange = 8,
    Sendmsg = 9,
    Recvmsg = 10,
    Timeout = 11,
    TimeoutRemove = 12,
    Accept = 13,
    AsyncCancel = 14,
    LinkTimeout = 15,
    Connect = 16,
    Fallocate = 17,
    Openat = 18,
    Close = 19,
    FilesUpdate = 20,
    Statx = 21,
    Read = 22,
    Write = 23,
    Fadvise = 24,
    Madvise = 25,
    Send = 26,
    Recv = 27,
    Openat2 = 28,
    EpollCtl = 29,
    Splice = 30,
    ProvideBuffers = 31,
    RemoveBuffers = 32,
    Tee = 33,
    Shutdown = 34,
    Renameat = 35,
    Unlinkat = 36,
    Mkdirat = 37,
    Symlinkat = 38,
    Linkat = 39,
    MsgRing = 40,
    Fsetxattr = 41,
    Setxattr = 42,
    Fgetxattr = 43,
    Getxattr = 44,
    Socket = 45,
    UringCmd = 46,
    SendZc = 47,
    SendmsgZc = 48,
    ReadMultishot = 49,
    WaitId = 50,
    Futex = 51,
    FutexWaitv = 52,
    // Zxyphor
    ZxyBatchIo = 200,
    ZxyCryptoOp = 201,
}

/// io_uring setup flags
pub const IORING_SETUP_IOPOLL: u32 = 1 << 0;
pub const IORING_SETUP_SQPOLL: u32 = 1 << 1;
pub const IORING_SETUP_SQ_AFF: u32 = 1 << 2;
pub const IORING_SETUP_CQSIZE: u32 = 1 << 3;
pub const IORING_SETUP_CLAMP: u32 = 1 << 4;
pub const IORING_SETUP_ATTACH_WQ: u32 = 1 << 5;
pub const IORING_SETUP_R_DISABLED: u32 = 1 << 6;
pub const IORING_SETUP_SUBMIT_ALL: u32 = 1 << 7;
pub const IORING_SETUP_COOP_TASKRUN: u32 = 1 << 8;
pub const IORING_SETUP_TASKRUN_FLAG: u32 = 1 << 9;
pub const IORING_SETUP_SQE128: u32 = 1 << 10;
pub const IORING_SETUP_CQE32: u32 = 1 << 11;
pub const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 12;
pub const IORING_SETUP_DEFER_TASKRUN: u32 = 1 << 13;
pub const IORING_SETUP_NO_MMAP: u32 = 1 << 14;
pub const IORING_SETUP_REGISTERED_FD_ONLY: u32 = 1 << 15;
pub const IORING_SETUP_NO_SQARRAY: u32 = 1 << 16;

/// io_uring SQE flags
pub const IOSQE_FIXED_FILE: u8 = 1 << 0;
pub const IOSQE_IO_DRAIN: u8 = 1 << 1;
pub const IOSQE_IO_LINK: u8 = 1 << 2;
pub const IOSQE_IO_HARDLINK: u8 = 1 << 3;
pub const IOSQE_ASYNC: u8 = 1 << 4;
pub const IOSQE_BUFFER_SELECT: u8 = 1 << 5;
pub const IOSQE_CQE_SKIP_SUCCESS: u8 = 1 << 6;

/// io_uring instance info
#[derive(Debug, Clone)]
pub struct IoUringInfo {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    // Features
    pub features: u32,
    // Stats
    pub total_sqes_submitted: u64,
    pub total_cqes_completed: u64,
    pub total_sq_overflows: u64,
    pub total_cq_overflows: u64,
    // Registered
    pub nr_registered_files: u32,
    pub nr_registered_buffers: u32,
    // sqpoll
    pub sqpoll_thread_active: bool,
}

// ============================================================================
// fallocate
// ============================================================================

/// fallocate mode flags
pub const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
pub const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;
pub const FALLOC_FL_NO_HIDE_STALE: u32 = 0x04;
pub const FALLOC_FL_COLLAPSE_RANGE: u32 = 0x08;
pub const FALLOC_FL_ZERO_RANGE: u32 = 0x10;
pub const FALLOC_FL_INSERT_RANGE: u32 = 0x20;
pub const FALLOC_FL_UNSHARE_RANGE: u32 = 0x40;

// ============================================================================
// inotify / fanotify
// ============================================================================

/// inotify event mask
pub const IN_ACCESS: u32 = 0x00000001;
pub const IN_MODIFY: u32 = 0x00000002;
pub const IN_ATTRIB: u32 = 0x00000004;
pub const IN_CLOSE_WRITE: u32 = 0x00000008;
pub const IN_CLOSE_NOWRITE: u32 = 0x00000010;
pub const IN_OPEN: u32 = 0x00000020;
pub const IN_MOVED_FROM: u32 = 0x00000040;
pub const IN_MOVED_TO: u32 = 0x00000080;
pub const IN_CREATE: u32 = 0x00000100;
pub const IN_DELETE: u32 = 0x00000200;
pub const IN_DELETE_SELF: u32 = 0x00000400;
pub const IN_MOVE_SELF: u32 = 0x00000800;
pub const IN_UNMOUNT: u32 = 0x00002000;
pub const IN_Q_OVERFLOW: u32 = 0x00004000;
pub const IN_IGNORED: u32 = 0x00008000;
pub const IN_ONLYDIR: u32 = 0x01000000;
pub const IN_DONT_FOLLOW: u32 = 0x02000000;
pub const IN_EXCL_UNLINK: u32 = 0x04000000;
pub const IN_MASK_CREATE: u32 = 0x10000000;
pub const IN_MASK_ADD: u32 = 0x20000000;
pub const IN_ISDIR: u32 = 0x40000000;
pub const IN_ONESHOT: u32 = 0x80000000;
pub const IN_ALL_EVENTS: u32 = 0x00000FFF;

/// fanotify init flags
pub const FAN_CLOEXEC: u32 = 0x00000001;
pub const FAN_NONBLOCK: u32 = 0x00000002;
pub const FAN_CLASS_NOTIF: u32 = 0x00000000;
pub const FAN_CLASS_CONTENT: u32 = 0x00000004;
pub const FAN_CLASS_PRE_CONTENT: u32 = 0x00000008;
pub const FAN_UNLIMITED_QUEUE: u32 = 0x00000010;
pub const FAN_UNLIMITED_MARKS: u32 = 0x00000020;
pub const FAN_ENABLE_AUDIT: u32 = 0x00000040;
pub const FAN_REPORT_TID: u32 = 0x00000100;
pub const FAN_REPORT_FID: u32 = 0x00000200;
pub const FAN_REPORT_DIR_FID: u32 = 0x00000400;
pub const FAN_REPORT_NAME: u32 = 0x00000800;
pub const FAN_REPORT_TARGET_FID: u32 = 0x00001000;
pub const FAN_REPORT_PIDFD: u32 = 0x00000080;

/// fanotify event mask
pub const FAN_ACCESS: u64 = 0x00000001;
pub const FAN_MODIFY: u64 = 0x00000002;
pub const FAN_ATTRIB: u64 = 0x00000004;
pub const FAN_CLOSE_WRITE: u64 = 0x00000008;
pub const FAN_CLOSE_NOWRITE: u64 = 0x00000010;
pub const FAN_OPEN: u64 = 0x00000020;
pub const FAN_MOVED_FROM: u64 = 0x00000040;
pub const FAN_MOVED_TO: u64 = 0x00000080;
pub const FAN_CREATE: u64 = 0x00000100;
pub const FAN_DELETE: u64 = 0x00000200;
pub const FAN_DELETE_SELF: u64 = 0x00000400;
pub const FAN_MOVE_SELF: u64 = 0x00000800;
pub const FAN_OPEN_EXEC: u64 = 0x00001000;
pub const FAN_Q_OVERFLOW: u64 = 0x00004000;
pub const FAN_FS_ERROR: u64 = 0x00008000;
pub const FAN_OPEN_PERM: u64 = 0x00010000;
pub const FAN_ACCESS_PERM: u64 = 0x00020000;
pub const FAN_OPEN_EXEC_PERM: u64 = 0x00040000;
pub const FAN_RENAME: u64 = 0x10000000;
pub const FAN_PRE_ACCESS: u64 = 0x00080000;

/// fanotify watch info
#[derive(Debug, Clone)]
pub struct FanotifyWatch {
    pub mask: u64,
    pub flags: u32,
    pub mark_type: FanotifyMarkType,
    pub path_offset: u32,
    pub path_len: u16,
}

/// fanotify mark type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanotifyMarkType {
    Inode = 0,
    Mount = 0x10,
    Filesystem = 0x100,
}

// ============================================================================
// Directory entry types
// ============================================================================

/// Directory entry type (d_type in readdir)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirentType {
    Unknown = 0,
    Fifo = 1,
    Chr = 2,
    Dir = 4,
    Blk = 6,
    Reg = 8,
    Lnk = 10,
    Sock = 12,
    Wht = 14,        // Whiteout (overlayfs)
}

/// getdents64 entry
#[derive(Debug, Clone)]
pub struct LinuxDirent64 {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: DirentType,
    pub d_name_len: u16,
}

// ============================================================================
// statx
// ============================================================================

/// statx mask
pub const STATX_TYPE: u32 = 0x00000001;
pub const STATX_MODE: u32 = 0x00000002;
pub const STATX_NLINK: u32 = 0x00000004;
pub const STATX_UID: u32 = 0x00000008;
pub const STATX_GID: u32 = 0x00000010;
pub const STATX_ATIME: u32 = 0x00000020;
pub const STATX_MTIME: u32 = 0x00000040;
pub const STATX_CTIME: u32 = 0x00000080;
pub const STATX_INO: u32 = 0x00000100;
pub const STATX_SIZE: u32 = 0x00000200;
pub const STATX_BLOCKS: u32 = 0x00000400;
pub const STATX_BASIC_STATS: u32 = 0x000007FF;
pub const STATX_BTIME: u32 = 0x00000800;     // Birth time
pub const STATX_MNT_ID: u32 = 0x00001000;
pub const STATX_DIOALIGN: u32 = 0x00002000;  // Direct I/O alignment
pub const STATX_MNT_ID_UNIQUE: u32 = 0x00004000;
pub const STATX_SUBVOL: u32 = 0x00008000;

/// statx attributes
pub const STATX_ATTR_COMPRESSED: u64 = 0x00000004;
pub const STATX_ATTR_IMMUTABLE: u64 = 0x00000010;
pub const STATX_ATTR_APPEND: u64 = 0x00000020;
pub const STATX_ATTR_NODUMP: u64 = 0x00000040;
pub const STATX_ATTR_ENCRYPTED: u64 = 0x00000800;
pub const STATX_ATTR_AUTOMOUNT: u64 = 0x00001000;
pub const STATX_ATTR_MOUNT_ROOT: u64 = 0x00002000;
pub const STATX_ATTR_VERITY: u64 = 0x00100000;
pub const STATX_ATTR_DAX: u64 = 0x00200000;

/// statx data
#[derive(Debug, Clone)]
pub struct StatxData {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_attributes_mask: u64,
    // Timestamps
    pub stx_atime_sec: i64,
    pub stx_atime_nsec: u32,
    pub stx_btime_sec: i64,
    pub stx_btime_nsec: u32,
    pub stx_ctime_sec: i64,
    pub stx_ctime_nsec: u32,
    pub stx_mtime_sec: i64,
    pub stx_mtime_nsec: u32,
    // Device
    pub stx_rdev_major: u32,
    pub stx_rdev_minor: u32,
    pub stx_dev_major: u32,
    pub stx_dev_minor: u32,
    // Mount ID
    pub stx_mnt_id: u64,
    // DIO alignment
    pub stx_dio_mem_align: u32,
    pub stx_dio_offset_align: u32,
    // Subvolume
    pub stx_subvol: u64,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

/// Filesystem features subsystem
#[derive(Debug, Clone)]
pub struct FsFeaturesSubsystem {
    // fscrypt
    pub nr_encrypted_inodes: u64,
    pub nr_encryption_policies: u32,
    pub nr_master_keys: u32,
    // fsverity
    pub nr_verity_files: u64,
    pub nr_verity_verifications: u64,
    pub nr_verity_failures: u64,
    // io_uring
    pub nr_io_uring_instances: u32,
    pub total_sqes: u64,
    pub total_cqes: u64,
    // inotify/fanotify
    pub nr_inotify_instances: u32,
    pub nr_inotify_watches: u64,
    pub nr_fanotify_groups: u32,
    pub nr_fanotify_marks: u64,
    pub total_fs_events: u64,
    // fallocate
    pub total_fallocates: u64,
    pub total_punch_holes: u64,
    pub total_zero_ranges: u64,
    // Stats
    pub total_statx_calls: u64,
    pub total_getdents: u64,
    // Zxyphor
    pub zxy_inline_crypto: bool,
    pub initialized: bool,
}
