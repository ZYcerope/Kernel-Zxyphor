//! Kernel Zxyphor — Advanced Virtual Filesystem Layer (Rust)
//!
//! Extended VFS implementation providing:
//! - Dentry cache (dcache) with LRU eviction
//! - Inode cache (icache) with reference counting
//! - Mount namespace support
//! - File locking (POSIX and flock)
//! - Extended attributes (xattr)
//! - Access control lists (ACL)
//! - File system notifications (inotify/fanotify)
//! - Direct I/O support
//! - Asynchronous I/O (AIO) infrastructure

#![no_std]
#![allow(dead_code)]

use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU32, AtomicU64, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum path component length
const NAME_MAX: usize = 255;
/// Maximum full path length
const PATH_MAX: usize = 4096;
/// Maximum symlink depth
const MAX_SYMLINK_DEPTH: usize = 40;
/// Maximum number of mounted filesystems
const MAX_MOUNTS: usize = 256;
/// Maximum open files per process
const MAX_OPEN_FILES: usize = 1024;
/// Maximum xattr name length
const XATTR_NAME_MAX: usize = 255;
/// Maximum xattr value size (64 KiB)
const XATTR_SIZE_MAX: usize = 65536;
/// Dentry cache size
const DCACHE_SIZE: usize = 16384;
/// Inode cache size
const ICACHE_SIZE: usize = 8192;

// ============================================================================
// File Types and Modes
// ============================================================================

/// File type bits in st_mode
pub mod file_type {
    pub const S_IFMT: u32 = 0o170000;
    pub const S_IFSOCK: u32 = 0o140000;
    pub const S_IFLNK: u32 = 0o120000;
    pub const S_IFREG: u32 = 0o100000;
    pub const S_IFBLK: u32 = 0o060000;
    pub const S_IFDIR: u32 = 0o040000;
    pub const S_IFCHR: u32 = 0o020000;
    pub const S_IFIFO: u32 = 0o010000;
}

/// Permission bits
pub mod perm {
    pub const S_ISUID: u32 = 0o4000;
    pub const S_ISGID: u32 = 0o2000;
    pub const S_ISVTX: u32 = 0o1000;
    pub const S_IRWXU: u32 = 0o0700;
    pub const S_IRUSR: u32 = 0o0400;
    pub const S_IWUSR: u32 = 0o0200;
    pub const S_IXUSR: u32 = 0o0100;
    pub const S_IRWXG: u32 = 0o0070;
    pub const S_IRGRP: u32 = 0o0040;
    pub const S_IWGRP: u32 = 0o0020;
    pub const S_IXGRP: u32 = 0o0010;
    pub const S_IRWXO: u32 = 0o0007;
    pub const S_IROTH: u32 = 0o0004;
    pub const S_IWOTH: u32 = 0o0002;
    pub const S_IXOTH: u32 = 0o0001;
}

/// Open flags
pub mod open_flags {
    pub const O_RDONLY: u32 = 0;
    pub const O_WRONLY: u32 = 1;
    pub const O_RDWR: u32 = 2;
    pub const O_CREAT: u32 = 0o100;
    pub const O_EXCL: u32 = 0o200;
    pub const O_NOCTTY: u32 = 0o400;
    pub const O_TRUNC: u32 = 0o1000;
    pub const O_APPEND: u32 = 0o2000;
    pub const O_NONBLOCK: u32 = 0o4000;
    pub const O_DSYNC: u32 = 0o10000;
    pub const O_SYNC: u32 = 0o4010000;
    pub const O_DIRECT: u32 = 0o40000;
    pub const O_LARGEFILE: u32 = 0o100000;
    pub const O_DIRECTORY: u32 = 0o200000;
    pub const O_NOFOLLOW: u32 = 0o400000;
    pub const O_NOATIME: u32 = 0o1000000;
    pub const O_CLOEXEC: u32 = 0o2000000;
    pub const O_TMPFILE: u32 = 0o20200000;
    pub const O_PATH: u32 = 0o10000000;
}

/// Seek whence
pub mod seek {
    pub const SEEK_SET: u32 = 0;
    pub const SEEK_CUR: u32 = 1;
    pub const SEEK_END: u32 = 2;
    pub const SEEK_DATA: u32 = 3;
    pub const SEEK_HOLE: u32 = 4;
}

/// File lock types
pub mod lock_type {
    pub const F_RDLCK: i32 = 0;
    pub const F_WRLCK: i32 = 1;
    pub const F_UNLCK: i32 = 2;
}

// ============================================================================
// Error Codes
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum VfsError {
    PermissionDenied = -1,
    FileNotFound = -2,
    ProcessNotFound = -3,
    Interrupted = -4,
    IoError = -5,
    NoSuchDevice = -6,
    ArgumentListTooLong = -7,
    ExecFormatError = -8,
    BadFileDescriptor = -9,
    NoChildProcess = -10,
    TryAgain = -11,
    OutOfMemory = -12,
    AccessDenied = -13,
    BadAddress = -14,
    DeviceBusy = -16,
    FileExists = -17,
    CrossDeviceLink = -18,
    NotADirectory = -20,
    IsADirectory = -21,
    InvalidArgument = -22,
    TooManyOpenFiles = -24,
    NotATerminal = -25,
    FileTooLarge = -27,
    NoSpaceLeft = -28,
    IllegalSeek = -29,
    ReadOnlyFilesystem = -30,
    TooManyLinks = -31,
    BrokenPipe = -32,
    NameTooLong = -36,
    NoLocks = -37,
    NotImplemented = -38,
    DirectoryNotEmpty = -39,
    TooManySymlinks = -40,
    Stale = -116,
}

pub type VfsResult<T> = Result<T, VfsError>;

// ============================================================================
// Timespec
// ============================================================================

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

impl Timespec {
    pub const ZERO: Timespec = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    pub fn now() -> Self {
        // TODO: Get actual time from kernel clock
        Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }
    }
}

// ============================================================================
// Inode — In-memory representation of a file/directory
// ============================================================================

/// Inode structure — represents a file object in the VFS.
#[repr(C)]
pub struct Inode {
    /// Inode number (unique within filesystem)
    pub ino: u64,
    /// File type and permissions
    pub mode: u32,
    /// Number of hard links
    pub nlink: AtomicU32,
    /// Owner UID
    pub uid: u32,
    /// Owner GID
    pub gid: u32,
    /// File size in bytes
    pub size: AtomicI64,
    /// Last access time
    pub atime: Timespec,
    /// Last modification time
    pub mtime: Timespec,
    /// Last status change time
    pub ctime: Timespec,
    /// Creation time (birthtime)
    pub btime: Timespec,
    /// Block size for I/O
    pub blksize: u32,
    /// Number of 512-byte blocks allocated
    pub blocks: u64,
    /// Device ID (for device files)
    pub rdev: u64,
    /// Device ID of the filesystem
    pub dev: u64,
    /// Reference count
    pub ref_count: AtomicU32,
    /// Dirty flag (needs writeback)
    pub dirty: AtomicBool,
    /// Generation number (for NFS)
    pub generation: u32,
    /// Filesystem-specific operations
    pub ops: *const InodeOps,
    /// Filesystem-specific data
    pub fs_data: *mut u8,
    /// Superblock pointer
    pub sb: *mut Superblock,
    /// Extended attributes head
    pub xattrs: *mut Xattr,
    /// File lock list
    pub locks: *mut FileLock,
    /// Inode flags (append-only, immutable, etc.)
    pub flags: u32,
}

unsafe impl Send for Inode {}
unsafe impl Sync for Inode {}

impl Inode {
    pub fn new(ino: u64, mode: u32) -> Self {
        let now = Timespec::now();
        Inode {
            ino,
            mode,
            nlink: AtomicU32::new(1),
            uid: 0,
            gid: 0,
            size: AtomicI64::new(0),
            atime: now,
            mtime: now,
            ctime: now,
            btime: now,
            blksize: 4096,
            blocks: 0,
            rdev: 0,
            dev: 0,
            ref_count: AtomicU32::new(1),
            dirty: AtomicBool::new(false),
            generation: 0,
            ops: ptr::null(),
            fs_data: ptr::null_mut(),
            sb: ptr::null_mut(),
            xattrs: ptr::null_mut(),
            locks: ptr::null_mut(),
            flags: 0,
        }
    }

    pub fn is_dir(&self) -> bool {
        (self.mode & file_type::S_IFMT) == file_type::S_IFDIR
    }

    pub fn is_regular(&self) -> bool {
        (self.mode & file_type::S_IFMT) == file_type::S_IFREG
    }

    pub fn is_symlink(&self) -> bool {
        (self.mode & file_type::S_IFMT) == file_type::S_IFLNK
    }

    pub fn is_block_device(&self) -> bool {
        (self.mode & file_type::S_IFMT) == file_type::S_IFBLK
    }

    pub fn is_char_device(&self) -> bool {
        (self.mode & file_type::S_IFMT) == file_type::S_IFCHR
    }

    pub fn is_fifo(&self) -> bool {
        (self.mode & file_type::S_IFMT) == file_type::S_IFIFO
    }

    pub fn is_socket(&self) -> bool {
        (self.mode & file_type::S_IFMT) == file_type::S_IFSOCK
    }

    pub fn get_ref(&self) {
        self.ref_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn put_ref(&self) -> bool {
        self.ref_count.fetch_sub(1, Ordering::Release) == 1
    }

    /// Check permission for the given operation.
    pub fn check_permission(&self, uid: u32, gid: u32, mask: u32) -> bool {
        // Root can do anything
        if uid == 0 {
            return true;
        }

        let mode = self.mode;
        let perm_bits = if uid == self.uid {
            (mode >> 6) & 7
        } else if gid == self.gid {
            (mode >> 3) & 7
        } else {
            mode & 7
        };

        (perm_bits & mask) == mask
    }

    /// Mark the inode as dirty.
    pub fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Release);
    }
}

// ============================================================================
// Inode Operations (Virtual Method Table)
// ============================================================================

/// Operations provided by the filesystem for inode manipulation.
#[repr(C)]
pub struct InodeOps {
    /// Look up a child entry in a directory
    pub lookup: Option<fn(dir: *mut Inode, name: &[u8]) -> VfsResult<*mut Dentry>>,
    /// Create a new file
    pub create: Option<fn(dir: *mut Inode, name: &[u8], mode: u32) -> VfsResult<*mut Inode>>,
    /// Create a directory
    pub mkdir: Option<fn(dir: *mut Inode, name: &[u8], mode: u32) -> VfsResult<*mut Inode>>,
    /// Remove a file
    pub unlink: Option<fn(dir: *mut Inode, name: &[u8]) -> VfsResult<()>>,
    /// Remove a directory
    pub rmdir: Option<fn(dir: *mut Inode, name: &[u8]) -> VfsResult<()>>,
    /// Create a symlink
    pub symlink: Option<fn(dir: *mut Inode, name: &[u8], target: &[u8]) -> VfsResult<*mut Inode>>,
    /// Create a hard link
    pub link: Option<fn(old: *mut Inode, dir: *mut Inode, name: &[u8]) -> VfsResult<()>>,
    /// Rename a file/directory
    pub rename:
        Option<fn(old_dir: *mut Inode, old_name: &[u8], new_dir: *mut Inode, new_name: &[u8]) -> VfsResult<()>>,
    /// Read a symlink target
    pub readlink: Option<fn(inode: *mut Inode, buf: &mut [u8]) -> VfsResult<usize>>,
    /// Get file attributes
    pub getattr: Option<fn(inode: *mut Inode, stat: *mut StatBuf) -> VfsResult<()>>,
    /// Set file attributes
    pub setattr: Option<fn(inode: *mut Inode, attr: *const InodeAttr) -> VfsResult<()>>,
    /// Create a device node
    pub mknod: Option<fn(dir: *mut Inode, name: &[u8], mode: u32, dev: u64) -> VfsResult<*mut Inode>>,
    /// Truncate file
    pub truncate: Option<fn(inode: *mut Inode, size: i64) -> VfsResult<()>>,
}

/// Attributes to set on an inode.
#[repr(C)]
pub struct InodeAttr {
    pub valid: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: i64,
    pub atime: Timespec,
    pub mtime: Timespec,
}

pub const ATTR_MODE: u32 = 1 << 0;
pub const ATTR_UID: u32 = 1 << 1;
pub const ATTR_GID: u32 = 1 << 2;
pub const ATTR_SIZE: u32 = 1 << 3;
pub const ATTR_ATIME: u32 = 1 << 4;
pub const ATTR_MTIME: u32 = 1 << 5;
pub const ATTR_CTIME: u32 = 1 << 6;

// ============================================================================
// Stat Buffer
// ============================================================================

#[repr(C)]
pub struct StatBuf {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub _pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: Timespec,
    pub st_mtime: Timespec,
    pub st_ctime: Timespec,
    pub _reserved: [i64; 3],
}

impl StatBuf {
    pub fn from_inode(inode: &Inode) -> Self {
        StatBuf {
            st_dev: inode.dev,
            st_ino: inode.ino,
            st_nlink: inode.nlink.load(Ordering::Relaxed) as u64,
            st_mode: inode.mode,
            st_uid: inode.uid,
            st_gid: inode.gid,
            _pad0: 0,
            st_rdev: inode.rdev,
            st_size: inode.size.load(Ordering::Relaxed),
            st_blksize: inode.blksize as i64,
            st_blocks: inode.blocks as i64,
            st_atime: inode.atime,
            st_mtime: inode.mtime,
            st_ctime: inode.ctime,
            _reserved: [0; 3],
        }
    }
}

// ============================================================================
// Dentry — Directory Entry Cache
// ============================================================================

/// Dentry (directory entry) — cached name-to-inode mapping.
#[repr(C)]
pub struct Dentry {
    /// Entry name
    pub name: [u8; NAME_MAX + 1],
    /// Name length
    pub name_len: u16,
    /// Associated inode
    pub inode: *mut Inode,
    /// Parent dentry
    pub parent: *mut Dentry,
    /// Children list head
    pub children: *mut Dentry,
    /// Next sibling
    pub next_sibling: *mut Dentry,
    /// Hash list next (for dcache lookup)
    pub hash_next: *mut Dentry,
    /// Reference count
    pub ref_count: AtomicU32,
    /// Flags
    pub flags: u32,
    /// Mount point (if this dentry is a mountpoint)
    pub mount: *mut Mount,
    /// Superblock
    pub sb: *mut Superblock,
}

unsafe impl Send for Dentry {}
unsafe impl Sync for Dentry {}

/// Dentry flags
pub const DCACHE_ENTRY_TYPE: u32 = 0x07;
pub const DCACHE_MISS_TYPE: u32 = 0x00; // Negative dentry
pub const DCACHE_REGULAR_TYPE: u32 = 0x01;
pub const DCACHE_DIRECTORY_TYPE: u32 = 0x02;
pub const DCACHE_SYMLINK_TYPE: u32 = 0x03;
pub const DCACHE_MOUNTED: u32 = 0x10;
pub const DCACHE_DISCONNECTED: u32 = 0x20;

impl Dentry {
    pub fn new(name: &[u8], parent: *mut Dentry) -> Self {
        let mut d = Dentry {
            name: [0; NAME_MAX + 1],
            name_len: name.len().min(NAME_MAX) as u16,
            inode: ptr::null_mut(),
            parent,
            children: ptr::null_mut(),
            next_sibling: ptr::null_mut(),
            hash_next: ptr::null_mut(),
            ref_count: AtomicU32::new(1),
            flags: 0,
            mount: ptr::null_mut(),
            sb: ptr::null_mut(),
        };
        let len = name.len().min(NAME_MAX);
        d.name[..len].copy_from_slice(&name[..len]);
        d
    }

    pub fn is_negative(&self) -> bool {
        self.inode.is_null()
    }

    pub fn is_root(&self) -> bool {
        self.parent.is_null() || ptr::eq(self.parent, self as *const _ as *mut _)
    }

    pub fn is_mountpoint(&self) -> bool {
        self.flags & DCACHE_MOUNTED != 0
    }

    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

// ============================================================================
// File — Open file instance
// ============================================================================

/// An open file descriptor.
#[repr(C)]
pub struct File {
    /// Dentry this file was opened from
    pub dentry: *mut Dentry,
    /// Inode
    pub inode: *mut Inode,
    /// Current file position
    pub pos: AtomicI64,
    /// Open flags
    pub flags: u32,
    /// File mode (permissions at time of open)
    pub mode: u32,
    /// Reference count
    pub ref_count: AtomicU32,
    /// File operations
    pub ops: *const FileOps,
    /// Private data (filesystem-specific)
    pub private_data: *mut u8,
    /// Owner PID
    pub owner_pid: u32,
    /// Async notification info
    pub fasync: *mut u8,
}

unsafe impl Send for File {}
unsafe impl Sync for File {}

impl File {
    pub fn new(
        dentry: *mut Dentry,
        inode: *mut Inode,
        flags: u32,
        ops: *const FileOps,
    ) -> Self {
        File {
            dentry,
            inode,
            pos: AtomicI64::new(0),
            flags,
            mode: 0,
            ref_count: AtomicU32::new(1),
            ops,
            private_data: ptr::null_mut(),
            owner_pid: 0,
            fasync: ptr::null_mut(),
        }
    }

    pub fn can_read(&self) -> bool {
        let access = self.flags & 3;
        access == open_flags::O_RDONLY || access == open_flags::O_RDWR
    }

    pub fn can_write(&self) -> bool {
        let access = self.flags & 3;
        access == open_flags::O_WRONLY || access == open_flags::O_RDWR
    }

    pub fn is_append(&self) -> bool {
        self.flags & open_flags::O_APPEND != 0
    }

    pub fn is_nonblock(&self) -> bool {
        self.flags & open_flags::O_NONBLOCK != 0
    }

    pub fn is_direct(&self) -> bool {
        self.flags & open_flags::O_DIRECT != 0
    }
}

// ============================================================================
// File Operations (Virtual Method Table)
// ============================================================================

/// Operations provided by the filesystem for file manipulation.
#[repr(C)]
pub struct FileOps {
    /// Read data from file
    pub read: Option<fn(file: *mut File, buf: *mut u8, count: usize, offset: *mut i64) -> VfsResult<usize>>,
    /// Write data to file
    pub write: Option<fn(file: *mut File, buf: *const u8, count: usize, offset: *mut i64) -> VfsResult<usize>>,
    /// Read directory entries
    pub readdir:
        Option<fn(file: *mut File, ctx: *mut DirentContext) -> VfsResult<usize>>,
    /// Memory-map the file
    pub mmap: Option<fn(file: *mut File, vma: *mut u8) -> VfsResult<()>>,
    /// Open file hook
    pub open: Option<fn(inode: *mut Inode, file: *mut File) -> VfsResult<()>>,
    /// Release (close) file hook
    pub release: Option<fn(inode: *mut Inode, file: *mut File) -> VfsResult<()>>,
    /// Flush file data
    pub flush: Option<fn(file: *mut File) -> VfsResult<()>>,
    /// Sync file data to storage
    pub fsync: Option<fn(file: *mut File, datasync: bool) -> VfsResult<()>>,
    /// Ioctl
    pub ioctl: Option<fn(file: *mut File, cmd: u32, arg: u64) -> VfsResult<i64>>,
    /// Seek
    pub llseek: Option<fn(file: *mut File, offset: i64, whence: u32) -> VfsResult<i64>>,
    /// Poll for I/O readiness
    pub poll: Option<fn(file: *mut File, wait: *mut u8) -> u32>,
    /// Splice read
    pub splice_read: Option<fn(file: *mut File, offset: *mut i64, pipe: *mut u8, len: usize, flags: u32) -> VfsResult<usize>>,
    /// Splice write
    pub splice_write: Option<fn(pipe: *mut u8, file: *mut File, offset: *mut i64, len: usize, flags: u32) -> VfsResult<usize>>,
    /// Fallocate
    pub fallocate: Option<fn(file: *mut File, mode: u32, offset: i64, len: i64) -> VfsResult<()>>,
    /// Copy file range
    pub copy_file_range: Option<fn(src: *mut File, src_off: *mut i64, dst: *mut File, dst_off: *mut i64, count: usize, flags: u32) -> VfsResult<usize>>,
}

/// Directory entry callback context.
#[repr(C)]
pub struct DirentContext {
    /// Callback function pointer
    pub callback: Option<fn(ctx: *mut DirentContext, name: &[u8], ino: u64, dtype: u8) -> bool>,
    /// Position
    pub pos: i64,
    /// User buffer
    pub buf: *mut u8,
    /// Remaining buffer size
    pub buf_remaining: usize,
}

// ============================================================================
// Superblock — Filesystem instance
// ============================================================================

/// Superblock — per-mounted-filesystem data.
#[repr(C)]
pub struct Superblock {
    /// Filesystem type
    pub fs_type: *const FilesystemType,
    /// Block size
    pub block_size: u32,
    /// Maximum file size
    pub max_file_size: u64,
    /// Magic number
    pub magic: u64,
    /// Root dentry
    pub root: *mut Dentry,
    /// Mount flags
    pub flags: u32,
    /// Device identifier
    pub dev: u64,
    /// Block device (if any)
    pub bdev: *mut u8,
    /// Superblock operations
    pub ops: *const SuperOps,
    /// Filesystem-specific data
    pub fs_data: *mut u8,
    /// Dirty inode list
    pub dirty_inodes: *mut Inode,
    /// Number of dirty inodes
    pub nr_dirty: AtomicU32,
    /// Read-only flag
    pub read_only: AtomicBool,
    /// Frozen flag (for snapshots)
    pub frozen: AtomicBool,
}

unsafe impl Send for Superblock {}
unsafe impl Sync for Superblock {}

/// Superblock operations.
#[repr(C)]
pub struct SuperOps {
    /// Allocate a new inode
    pub alloc_inode: Option<fn(sb: *mut Superblock) -> *mut Inode>,
    /// Free an inode
    pub free_inode: Option<fn(inode: *mut Inode)>,
    /// Write dirty inode to disk
    pub write_inode: Option<fn(inode: *mut Inode, sync: bool) -> VfsResult<()>>,
    /// Delete an inode (when nlink drops to 0)
    pub delete_inode: Option<fn(inode: *mut Inode) -> VfsResult<()>>,
    /// Sync the filesystem
    pub sync_fs: Option<fn(sb: *mut Superblock, wait: bool) -> VfsResult<()>>,
    /// Get filesystem statistics
    pub statfs: Option<fn(sb: *mut Superblock, buf: *mut StatFs) -> VfsResult<()>>,
    /// Remount with new flags
    pub remount: Option<fn(sb: *mut Superblock, flags: u32, data: *const u8) -> VfsResult<()>>,
    /// Unmount cleanup
    pub put_super: Option<fn(sb: *mut Superblock)>,
    /// Freeze filesystem
    pub freeze_fs: Option<fn(sb: *mut Superblock) -> VfsResult<()>>,
    /// Unfreeze filesystem
    pub unfreeze_fs: Option<fn(sb: *mut Superblock) -> VfsResult<()>>,
}

/// Filesystem statistics.
#[repr(C)]
pub struct StatFs {
    pub f_type: u64,
    pub f_bsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_fsid: [u32; 2],
    pub f_namelen: u64,
    pub f_frsize: u64,
    pub f_flags: u64,
    pub f_spare: [u64; 4],
}

// ============================================================================
// Filesystem Type Registration
// ============================================================================

/// Registered filesystem type.
#[repr(C)]
pub struct FilesystemType {
    /// Filesystem name (e.g., "ext4", "tmpfs")
    pub name: [u8; 32],
    /// Filesystem flags
    pub fs_flags: u32,
    /// Mount operation
    pub mount: Option<fn(fs_type: *const FilesystemType, flags: u32, dev: *const u8, data: *const u8) -> VfsResult<*mut Superblock>>,
    /// Unmount cleanup
    pub kill_sb: Option<fn(sb: *mut Superblock)>,
    /// Next in registry
    pub next: *mut FilesystemType,
}

unsafe impl Send for FilesystemType {}
unsafe impl Sync for FilesystemType {}

/// Filesystem flags
pub const FS_REQUIRES_DEV: u32 = 1;
pub const FS_BINARY_MOUNTDATA: u32 = 2;
pub const FS_HAS_SUBTYPE: u32 = 4;
pub const FS_USERNS_MOUNT: u32 = 8;
pub const FS_RENAME_DOES_D_MOVE: u32 = 32768;

// ============================================================================
// Mount
// ============================================================================

/// Mount structure — represents a mounted filesystem instance.
#[repr(C)]
pub struct Mount {
    /// Superblock
    pub sb: *mut Superblock,
    /// Mount root dentry
    pub root: *mut Dentry,
    /// Mount point dentry (in parent filesystem)
    pub mountpoint: *mut Dentry,
    /// Parent mount
    pub parent: *mut Mount,
    /// Mount ID
    pub id: u32,
    /// Mount flags (MS_RDONLY, MS_NOSUID, etc.)
    pub flags: u32,
    /// Device name
    pub devname: [u8; 256],
    /// Mount namespace
    pub mnt_ns: *mut MountNamespace,
    /// Next mount in namespace
    pub next: *mut Mount,
    /// Children mounts
    pub children: *mut Mount,
    /// Reference count
    pub ref_count: AtomicU32,
}

unsafe impl Send for Mount {}
unsafe impl Sync for Mount {}

/// Mount flags
pub const MS_RDONLY: u32 = 1;
pub const MS_NOSUID: u32 = 2;
pub const MS_NODEV: u32 = 4;
pub const MS_NOEXEC: u32 = 8;
pub const MS_SYNCHRONOUS: u32 = 16;
pub const MS_REMOUNT: u32 = 32;
pub const MS_MANDLOCK: u32 = 64;
pub const MS_DIRSYNC: u32 = 128;
pub const MS_NOATIME: u32 = 1024;
pub const MS_NODIRATIME: u32 = 2048;
pub const MS_BIND: u32 = 4096;
pub const MS_MOVE: u32 = 8192;
pub const MS_REC: u32 = 16384;
pub const MS_SILENT: u32 = 32768;
pub const MS_RELATIME: u32 = 1 << 21;
pub const MS_LAZYTIME: u32 = 1 << 25;

// ============================================================================
// Mount Namespace
// ============================================================================

/// Mount namespace — isolated view of the filesystem hierarchy.
#[repr(C)]
pub struct MountNamespace {
    /// Root mount
    pub root: *mut Mount,
    /// List of all mounts in this namespace
    pub mounts: *mut Mount,
    /// Number of mounts
    pub nr_mounts: u32,
    /// Reference count
    pub ref_count: AtomicU32,
    /// Namespace ID
    pub ns_id: u64,
}

unsafe impl Send for MountNamespace {}
unsafe impl Sync for MountNamespace {}

// ============================================================================
// Extended Attributes (xattr)
// ============================================================================

/// Extended attribute entry.
#[repr(C)]
pub struct Xattr {
    /// Attribute name
    pub name: [u8; XATTR_NAME_MAX + 1],
    /// Name length
    pub name_len: u16,
    /// Value
    pub value: *mut u8,
    /// Value length
    pub value_len: u32,
    /// Next xattr
    pub next: *mut Xattr,
}

/// Xattr namespaces
pub mod xattr_ns {
    pub const XATTR_USER_PREFIX: &[u8] = b"user.";
    pub const XATTR_SYSTEM_PREFIX: &[u8] = b"system.";
    pub const XATTR_SECURITY_PREFIX: &[u8] = b"security.";
    pub const XATTR_TRUSTED_PREFIX: &[u8] = b"trusted.";
}

// ============================================================================
// File Locking
// ============================================================================

/// POSIX file lock.
#[repr(C)]
pub struct FileLock {
    /// Lock type (F_RDLCK, F_WRLCK, F_UNLCK)
    pub lock_type: i32,
    /// Owning PID
    pub pid: u32,
    /// Start offset
    pub start: i64,
    /// End offset (0 means EOF)
    pub end: i64,
    /// Next lock
    pub next: *mut FileLock,
    /// Is this a flock (whole-file) lock?
    pub is_flock: bool,
    /// Blocking waiters
    pub waiters: *mut u8,
}

// ============================================================================
// File Descriptor Table
// ============================================================================

/// Per-process file descriptor table.
pub struct FdTable {
    /// File pointers indexed by fd number
    pub files: [*mut File; MAX_OPEN_FILES],
    /// Close-on-exec bitmap
    pub close_on_exec: [u64; MAX_OPEN_FILES / 64],
    /// Number of open file descriptors
    pub count: u32,
    /// Maximum fd number in use + 1
    pub max_fd: u32,
}

impl FdTable {
    pub fn new() -> Self {
        FdTable {
            files: [ptr::null_mut(); MAX_OPEN_FILES],
            close_on_exec: [0; MAX_OPEN_FILES / 64],
            count: 0,
            max_fd: 0,
        }
    }

    /// Allocate the lowest available file descriptor.
    pub fn alloc_fd(&mut self, file: *mut File, min_fd: u32) -> VfsResult<i32> {
        for i in (min_fd as usize)..MAX_OPEN_FILES {
            if self.files[i].is_null() {
                self.files[i] = file;
                self.count += 1;
                if i as u32 >= self.max_fd {
                    self.max_fd = i as u32 + 1;
                }
                return Ok(i as i32);
            }
        }
        Err(VfsError::TooManyOpenFiles)
    }

    /// Get the file for a given fd.
    pub fn get_file(&self, fd: i32) -> VfsResult<*mut File> {
        if fd < 0 || fd as usize >= MAX_OPEN_FILES {
            return Err(VfsError::BadFileDescriptor);
        }
        let file = self.files[fd as usize];
        if file.is_null() {
            return Err(VfsError::BadFileDescriptor);
        }
        Ok(file)
    }

    /// Close a file descriptor.
    pub fn close_fd(&mut self, fd: i32) -> VfsResult<*mut File> {
        if fd < 0 || fd as usize >= MAX_OPEN_FILES {
            return Err(VfsError::BadFileDescriptor);
        }
        let file = self.files[fd as usize];
        if file.is_null() {
            return Err(VfsError::BadFileDescriptor);
        }
        self.files[fd as usize] = ptr::null_mut();
        self.clear_close_on_exec(fd);
        self.count -= 1;
        Ok(file)
    }

    /// Duplicate a file descriptor.
    pub fn dup_fd(&mut self, oldfd: i32, min_newfd: u32) -> VfsResult<i32> {
        let file = self.get_file(oldfd)?;
        // Increment refcount
        unsafe {
            (*file).ref_count.fetch_add(1, Ordering::Relaxed);
        }
        self.alloc_fd(file, min_newfd)
    }

    /// Duplicate fd to a specific number.
    pub fn dup2_fd(&mut self, oldfd: i32, newfd: i32) -> VfsResult<i32> {
        if oldfd == newfd {
            // Verify oldfd is valid
            let _ = self.get_file(oldfd)?;
            return Ok(newfd);
        }
        let old_file = self.get_file(oldfd)?;
        unsafe {
            (*old_file).ref_count.fetch_add(1, Ordering::Relaxed);
        }

        // Close newfd if open
        if !self.files[newfd as usize].is_null() {
            let _ = self.close_fd(newfd);
        }

        self.files[newfd as usize] = old_file;
        self.count += 1;
        if newfd as u32 >= self.max_fd {
            self.max_fd = newfd as u32 + 1;
        }
        Ok(newfd)
    }

    /// Close all fds marked close-on-exec.
    pub fn close_on_exec(&mut self) {
        for i in 0..self.max_fd as usize {
            if self.is_close_on_exec(i as i32) && !self.files[i].is_null() {
                let _ = self.close_fd(i as i32);
            }
        }
    }

    fn set_close_on_exec(&mut self, fd: i32) {
        let idx = fd as usize / 64;
        let bit = fd as usize % 64;
        if idx < self.close_on_exec.len() {
            self.close_on_exec[idx] |= 1 << bit;
        }
    }

    fn clear_close_on_exec(&mut self, fd: i32) {
        let idx = fd as usize / 64;
        let bit = fd as usize % 64;
        if idx < self.close_on_exec.len() {
            self.close_on_exec[idx] &= !(1 << bit);
        }
    }

    fn is_close_on_exec(&self, fd: i32) -> bool {
        let idx = fd as usize / 64;
        let bit = fd as usize % 64;
        if idx < self.close_on_exec.len() {
            self.close_on_exec[idx] & (1 << bit) != 0
        } else {
            false
        }
    }
}

// ============================================================================
// Path Resolution
// ============================================================================

/// Path walk flags.
pub mod walk_flags {
    pub const LOOKUP_FOLLOW: u32 = 0x0001;
    pub const LOOKUP_DIRECTORY: u32 = 0x0002;
    pub const LOOKUP_AUTOMOUNT: u32 = 0x0004;
    pub const LOOKUP_PARENT: u32 = 0x0010;
    pub const LOOKUP_REVAL: u32 = 0x0020;
    pub const LOOKUP_NO_SYMLINKS: u32 = 0x010000;
    pub const LOOKUP_NO_MAGICLINKS: u32 = 0x020000;
    pub const LOOKUP_NO_XDEV: u32 = 0x040000;
    pub const LOOKUP_BENEATH: u32 = 0x080000;
    pub const LOOKUP_IN_ROOT: u32 = 0x100000;
}

/// Namespace data for path resolution.
pub struct PathWalkContext {
    /// Current dentry
    pub dentry: *mut Dentry,
    /// Current mount
    pub mount: *mut Mount,
    /// Root dentry (for this namespace)
    pub root_dentry: *mut Dentry,
    /// Root mount
    pub root_mount: *mut Mount,
    /// Remaining symlink depth
    pub symlink_depth: u32,
    /// Walk flags
    pub flags: u32,
}

impl PathWalkContext {
    /// Follow a mount point.
    pub fn follow_mount(&mut self) -> bool {
        if self.dentry.is_null() {
            return false;
        }
        unsafe {
            if (*self.dentry).is_mountpoint() {
                // Follow to the mounted filesystem
                let mnt = (*self.dentry).mount;
                if !mnt.is_null() {
                    self.mount = mnt;
                    self.dentry = (*mnt).root;
                    return true;
                }
            }
        }
        false
    }

    /// Go up to parent directory.
    pub fn follow_dotdot(&mut self) -> bool {
        unsafe {
            if self.dentry.is_null() {
                return false;
            }
            // At filesystem root?
            if (*self.dentry).is_root() {
                // Check if at mount root
                if !self.mount.is_null() && !(*self.mount).parent.is_null() {
                    self.dentry = (*self.mount).mountpoint;
                    self.mount = (*self.mount).parent;
                    return true;
                }
                return false; // At absolute root
            }
            self.dentry = (*self.dentry).parent;
            true
        }
    }
}

// ============================================================================
// Inotify / Fanotify — File system event notifications
// ============================================================================

/// Inotify event.
#[repr(C)]
pub struct InotifyEvent {
    /// Watch descriptor
    pub wd: i32,
    /// Event mask
    pub mask: u32,
    /// Cookie (for rename events)
    pub cookie: u32,
    /// Name length
    pub len: u32,
    // Followed by name[len]
}

/// Inotify event mask
pub mod inotify_mask {
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
    pub const IN_ISDIR: u32 = 0x40000000;
}

/// Inotify watch.
pub struct InotifyWatch {
    pub wd: i32,
    pub mask: u32,
    pub inode: *mut Inode,
    pub next: *mut InotifyWatch,
}

/// Inotify instance.
pub struct InotifyInstance {
    pub watches: *mut InotifyWatch,
    pub event_queue: *mut InotifyEvent,
    pub event_count: u32,
    pub max_events: u32,
    pub next_wd: AtomicI32,
}

// ============================================================================
// Direct I/O Support
// ============================================================================

/// Direct I/O request.
#[repr(C)]
pub struct DirectIoReq {
    /// Block device or file
    pub file: *mut File,
    /// Operation (read/write)
    pub op: u32,
    /// File offset
    pub offset: i64,
    /// User buffer (must be page-aligned)
    pub buf: *mut u8,
    /// Length (must be block-aligned)
    pub len: usize,
    /// Completion callback
    pub callback: Option<fn(req: *mut DirectIoReq, result: i64)>,
    /// Private data
    pub private: *mut u8,
}

pub const DIO_READ: u32 = 0;
pub const DIO_WRITE: u32 = 1;

// ============================================================================
// Pipe Support
// ============================================================================

/// Pipe buffer.
pub struct PipeBuffer {
    /// Ring buffer data
    pub data: *mut u8,
    /// Buffer size (power of 2)
    pub size: usize,
    /// Read position
    pub read_pos: AtomicUsize,
    /// Write position
    pub write_pos: AtomicUsize,
    /// Number of readers
    pub readers: AtomicU32,
    /// Number of writers
    pub writers: AtomicU32,
}

impl PipeBuffer {
    pub fn available_read(&self) -> usize {
        let w = self.write_pos.load(Ordering::Acquire);
        let r = self.read_pos.load(Ordering::Acquire);
        w.wrapping_sub(r)
    }

    pub fn available_write(&self) -> usize {
        self.size - self.available_read()
    }

    pub fn is_empty(&self) -> bool {
        self.available_read() == 0
    }

    pub fn is_full(&self) -> bool {
        self.available_write() == 0
    }
}

// ============================================================================
// Filesystem Registry
// ============================================================================

/// Global filesystem type registry.
pub struct FsRegistry {
    head: *mut FilesystemType,
    count: u32,
}

unsafe impl Send for FsRegistry {}
unsafe impl Sync for FsRegistry {}

impl FsRegistry {
    pub const fn new() -> Self {
        FsRegistry {
            head: ptr::null_mut(),
            count: 0,
        }
    }

    /// Register a new filesystem type.
    pub fn register(&mut self, fs_type: *mut FilesystemType) -> VfsResult<()> {
        // Check for duplicates
        let mut curr = self.head;
        while !curr.is_null() {
            unsafe {
                if (*curr).name == (*fs_type).name {
                    return Err(VfsError::FileExists);
                }
                curr = (*curr).next;
            }
        }

        unsafe {
            (*fs_type).next = self.head;
        }
        self.head = fs_type;
        self.count += 1;
        Ok(())
    }

    /// Find a filesystem type by name.
    pub fn find(&self, name: &[u8]) -> Option<*mut FilesystemType> {
        let mut curr = self.head;
        while !curr.is_null() {
            unsafe {
                let fs_name_len = (*curr)
                    .name
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or((*curr).name.len());
                if &(*curr).name[..fs_name_len] == name {
                    return Some(curr);
                }
                curr = (*curr).next;
            }
        }
        None
    }

    /// Unregister a filesystem type.
    pub fn unregister(&mut self, name: &[u8]) -> VfsResult<()> {
        let mut prev: *mut *mut FilesystemType = &mut self.head;
        let mut curr = self.head;

        while !curr.is_null() {
            unsafe {
                let fs_name_len = (*curr)
                    .name
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or((*curr).name.len());
                if &(*curr).name[..fs_name_len] == name {
                    *prev = (*curr).next;
                    self.count -= 1;
                    return Ok(());
                }
                prev = &mut (*curr).next;
                curr = (*curr).next;
            }
        }

        Err(VfsError::FileNotFound)
    }
}

/// Global filesystem registry.
static mut FS_REGISTRY: FsRegistry = FsRegistry::new();

// ============================================================================
// VFS Initialization
// ============================================================================

/// Initialize the VFS subsystem.
#[no_mangle]
pub extern "C" fn vfs_init() -> i32 {
    // Register built-in filesystem types
    // (individual filesystem modules call register on init)
    0
}

/// Mount a filesystem.
#[no_mangle]
pub extern "C" fn vfs_mount(
    _fs_type_name: *const u8,
    _target: *const u8,
    _flags: u32,
    _data: *const u8,
) -> i32 {
    // TODO: Full mount implementation
    0
}

/// Unmount a filesystem.
#[no_mangle]
pub extern "C" fn vfs_umount(_target: *const u8, _flags: u32) -> i32 {
    // TODO: Full umount implementation
    0
}
