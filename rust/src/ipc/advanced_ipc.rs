// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced IPC (Rust)
// POSIX message queues, System V IPC, eventfd, signalfd, timerfd, io_uring advanced

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};

// ============================================================================
// POSIX Message Queue
// ============================================================================

pub const MQ_NAME_MAX: usize = 255;
pub const MQ_PRIO_MAX: u32 = 32768;
pub const MQ_MAX_MSG_SIZE: usize = 8192;

pub struct MqAttr {
    pub mq_flags: i64,      // Message queue flags (O_NONBLOCK)
    pub mq_maxmsg: i64,     // Max messages on queue
    pub mq_msgsize: i64,    // Max message size
    pub mq_curmsgs: i64,    // Current number of messages
}

pub struct MqMessage {
    pub priority: u32,
    pub size: u32,
    pub data: [u8; MQ_MAX_MSG_SIZE],
    pub sender_pid: i32,
    pub timestamp: u64,
}

pub struct PosixMq {
    pub name: [u8; MQ_NAME_MAX],
    pub name_len: u8,
    pub attr: MqAttr,
    pub messages: [MqMessage; 64],
    pub msg_count: u32,
    pub mode: u16,       // Permissions
    pub uid: u32,
    pub gid: u32,
    pub readers: AtomicU32,
    pub writers: AtomicU32,
    pub notify_pid: i32,
    pub notify_signo: i32,
    pub bytes_in_queue: AtomicU64,
}

impl PosixMq {
    pub fn send(&mut self, data: &[u8], priority: u32, pid: i32, ts: u64) -> bool {
        if self.msg_count as i64 >= self.attr.mq_maxmsg { return false; }
        if data.len() > self.attr.mq_msgsize as usize { return false; }
        
        let mut msg = MqMessage {
            priority,
            size: data.len() as u32,
            data: [0u8; MQ_MAX_MSG_SIZE],
            sender_pid: pid,
            timestamp: ts,
        };
        let copy_len = data.len().min(MQ_MAX_MSG_SIZE);
        msg.data[..copy_len].copy_from_slice(&data[..copy_len]);
        
        // Insert sorted by priority (highest first)
        let mut insert_idx = self.msg_count as usize;
        for i in 0..self.msg_count as usize {
            if self.messages[i].priority < priority {
                insert_idx = i;
                break;
            }
        }
        
        // Shift messages down
        if insert_idx < self.msg_count as usize {
            let count = self.msg_count as usize;
            for i in (insert_idx..count).rev() {
                if i + 1 < self.messages.len() {
                    self.messages[i + 1] = self.messages[i];
                }
            }
        }
        
        if insert_idx < self.messages.len() {
            self.messages[insert_idx] = msg;
            self.msg_count += 1;
            self.bytes_in_queue.fetch_add(data.len() as u64, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    pub fn receive(&mut self, buf: &mut [u8]) -> Option<(u32, u32)> {
        if self.msg_count == 0 { return None; }
        
        let msg = &self.messages[0];
        let size = (msg.size as usize).min(buf.len());
        buf[..size].copy_from_slice(&msg.data[..size]);
        let priority = msg.priority;
        let msg_size = msg.size;
        
        // Shift remaining messages up
        for i in 1..self.msg_count as usize {
            self.messages[i - 1] = self.messages[i];
        }
        self.msg_count -= 1;
        self.bytes_in_queue.fetch_sub(msg_size as u64, Ordering::Relaxed);
        
        Some((msg_size, priority))
    }
}

// ============================================================================
// System V IPC - Shared Memory
// ============================================================================

pub const IPC_CREAT: i32 = 0o1000;
pub const IPC_EXCL: i32 = 0o2000;
pub const IPC_NOWAIT: i32 = 0o4000;
pub const IPC_RMID: i32 = 0;
pub const IPC_SET: i32 = 1;
pub const IPC_STAT: i32 = 2;
pub const IPC_INFO: i32 = 3;
pub const IPC_PRIVATE: i32 = 0;

pub const SHM_HUGETLB: i32 = 0o4000;
pub const SHM_NORESERVE: i32 = 0o10000;
pub const SHM_RDONLY: i32 = 0o10000;
pub const SHM_RND: i32 = 0o20000;
pub const SHM_REMAP: i32 = 0o40000;
pub const SHM_EXEC: i32 = 0o100000;
pub const SHM_DEST: i32 = 0o1000;
pub const SHM_LOCKED: i32 = 0o2000;

#[repr(C)]
pub struct ShmidDs {
    pub shm_perm: IpcPerm,
    pub shm_segsz: u64,        // Size in bytes
    pub shm_atime: u64,        // Last attach time
    pub shm_dtime: u64,        // Last detach time
    pub shm_ctime: u64,        // Last change time
    pub shm_cpid: i32,         // Creator PID
    pub shm_lpid: i32,         // Last shmat/shmdt PID
    pub shm_nattch: u32,       // Number of attaches
}

#[repr(C)]
pub struct IpcPerm {
    pub key: i32,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    pub mode: u16,
    pub seq: u16,
}

pub struct ShmSegment {
    pub ds: ShmidDs,
    pub shmid: i32,
    pub pages: u64,
    pub page_pfns: [u64; 1024],    // Up to 4MB
    pub nr_pages: u32,
    pub flags: i32,
    pub hugepage: bool,
    pub numa_node: i32,
    pub attached_pids: [i32; 64],
    pub nr_attached: u32,
}

// ============================================================================
// System V IPC - Semaphores
// ============================================================================

pub const GETVAL: i32 = 12;
pub const SETVAL: i32 = 16;
pub const GETALL: i32 = 13;
pub const SETALL: i32 = 17;
pub const GETNCNT: i32 = 14;
pub const GETZCNT: i32 = 15;
pub const GETPID: i32 = 11;
pub const SEM_UNDO: i32 = 0x1000;
pub const SEM_STAT: i32 = 18;
pub const SEM_INFO: i32 = 19;

pub struct SysVSemaphoreSet {
    pub semid: i32,
    pub perm: IpcPerm,
    pub sem_otime: u64,        // Last semop time
    pub sem_ctime: u64,        // Last change time
    pub nsems: u32,
    pub semvals: [u16; 256],    // Semaphore values
    pub sempids: [i32; 256],    // Last PID to operate
    pub sem_pending: [SemOp; 128],
    pub nr_pending: u32,
}

#[repr(C)]
pub struct SemOp {
    pub sem_num: u16,
    pub sem_op: i16,
    pub sem_flg: i16,
}

pub struct SemUndo {
    pub semid: i32,
    pub adjustments: [i16; 256],
    pub task_pid: i32,
}

// ============================================================================
// System V IPC - Message Queues
// ============================================================================

pub const MSG_NOERROR: i32 = 0o10000;
pub const MSG_EXCEPT: i32 = 0o20000;
pub const MSG_COPY: i32 = 0o40000;
pub const MSGMNI: u32 = 32000;   // Max message queue IDs
pub const MSGMAX: u32 = 8192;    // Max message size
pub const MSGMNB: u32 = 16384;   // Max bytes on queue

#[repr(C)]
pub struct MsqidDs {
    pub msg_perm: IpcPerm,
    pub msg_stime: u64,
    pub msg_rtime: u64,
    pub msg_ctime: u64,
    pub msg_qnum: u64,
    pub msg_qbytes: u64,
    pub msg_lspid: i32,
    pub msg_lrpid: i32,
}

pub struct SysVMsgQueue {
    pub msqid: i32,
    pub ds: MsqidDs,
    pub messages: [SysVMsg; 256],
    pub msg_count: u32,
    pub total_bytes: u64,
}

pub struct SysVMsg {
    pub mtype: i64,         // Message type (> 0)
    pub msize: u32,
    pub data: [u8; 8192],
    pub sender_pid: i32,
    pub timestamp: u64,
}

// ============================================================================
// eventfd
// ============================================================================

pub struct EventFd {
    pub count: AtomicU64,
    pub flags: u32,
    pub max_count: u64,     // u64::MAX for non-semaphore, 1 for semaphore
}

pub const EFD_SEMAPHORE: u32 = 1;
pub const EFD_CLOEXEC: u32 = 0o2000000;
pub const EFD_NONBLOCK: u32 = 0o4000;

impl EventFd {
    pub fn new(initval: u64, flags: u32) -> Self {
        EventFd {
            count: AtomicU64::new(initval),
            flags,
            max_count: if flags & EFD_SEMAPHORE != 0 { 1 } else { u64::MAX - 1 },
        }
    }

    pub fn write(&self, val: u64) -> bool {
        let current = self.count.load(Ordering::Relaxed);
        if current > u64::MAX - 1 - val {
            return false; // Would overflow
        }
        self.count.fetch_add(val, Ordering::Release);
        true
    }

    pub fn read(&self) -> Option<u64> {
        if self.flags & EFD_SEMAPHORE != 0 {
            // Semaphore mode: decrement by 1
            let current = self.count.load(Ordering::Relaxed);
            if current == 0 { return None; }
            self.count.fetch_sub(1, Ordering::Release);
            Some(1)
        } else {
            // Normal mode: return entire count and reset
            let val = self.count.swap(0, Ordering::AcqRel);
            if val == 0 { None } else { Some(val) }
        }
    }
}

// ============================================================================
// signalfd
// ============================================================================

pub struct SignalFd {
    pub sigmask: u64,
    pub flags: u32,
    pub pending: [SignalFdInfo; 32],
    pub pending_count: AtomicU32,
}

#[repr(C)]
pub struct SignalFdInfo {
    pub ssi_signo: u32,
    pub ssi_errno: i32,
    pub ssi_code: i32,
    pub ssi_pid: u32,
    pub ssi_uid: u32,
    pub ssi_fd: i32,
    pub ssi_tid: u32,
    pub ssi_band: u32,
    pub ssi_overrun: u32,
    pub ssi_trapno: u32,
    pub ssi_status: i32,
    pub ssi_int: i32,
    pub ssi_ptr: u64,
    pub ssi_utime: u64,
    pub ssi_stime: u64,
    pub ssi_addr: u64,
    pub ssi_addr_lsb: u16,
    pub _pad: [u8; 46],
}

// ============================================================================
// timerfd
// ============================================================================

pub struct TimerFd {
    pub clock_id: u32,
    pub flags: u32,
    pub ticks: AtomicU64,
    pub interval_sec: u64,
    pub interval_nsec: u64,
    pub next_expiry_sec: u64,
    pub next_expiry_nsec: u64,
    pub settime_flags: u32,
    pub cancelled: AtomicBool,
}

pub const TFD_TIMER_ABSTIME: u32 = 1;
pub const TFD_TIMER_CANCEL_ON_SET: u32 = 2;
pub const TFD_CLOEXEC: u32 = 0o2000000;
pub const TFD_NONBLOCK: u32 = 0o4000;

impl TimerFd {
    pub fn fire(&self) -> u64 {
        self.ticks.fetch_add(1, Ordering::Release)
    }

    pub fn read_ticks(&self) -> u64 {
        self.ticks.swap(0, Ordering::AcqRel)
    }
}

// ============================================================================
// io_uring Advanced (Completion-based async I/O)
// ============================================================================

// io_uring opcodes (Linux 6.x compatible + extensions)
pub const IORING_OP_NOP: u8 = 0;
pub const IORING_OP_READV: u8 = 1;
pub const IORING_OP_WRITEV: u8 = 2;
pub const IORING_OP_FSYNC: u8 = 3;
pub const IORING_OP_READ_FIXED: u8 = 4;
pub const IORING_OP_WRITE_FIXED: u8 = 5;
pub const IORING_OP_POLL_ADD: u8 = 6;
pub const IORING_OP_POLL_REMOVE: u8 = 7;
pub const IORING_OP_SYNC_FILE_RANGE: u8 = 8;
pub const IORING_OP_SENDMSG: u8 = 9;
pub const IORING_OP_RECVMSG: u8 = 10;
pub const IORING_OP_TIMEOUT: u8 = 11;
pub const IORING_OP_TIMEOUT_REMOVE: u8 = 12;
pub const IORING_OP_ACCEPT: u8 = 13;
pub const IORING_OP_ASYNC_CANCEL: u8 = 14;
pub const IORING_OP_LINK_TIMEOUT: u8 = 15;
pub const IORING_OP_CONNECT: u8 = 16;
pub const IORING_OP_FALLOCATE: u8 = 17;
pub const IORING_OP_OPENAT: u8 = 18;
pub const IORING_OP_CLOSE: u8 = 19;
pub const IORING_OP_FILES_UPDATE: u8 = 20;
pub const IORING_OP_STATX: u8 = 21;
pub const IORING_OP_READ: u8 = 22;
pub const IORING_OP_WRITE: u8 = 23;
pub const IORING_OP_FADVISE: u8 = 24;
pub const IORING_OP_MADVISE: u8 = 25;
pub const IORING_OP_SEND: u8 = 26;
pub const IORING_OP_RECV: u8 = 27;
pub const IORING_OP_OPENAT2: u8 = 28;
pub const IORING_OP_EPOLL_CTL: u8 = 29;
pub const IORING_OP_SPLICE: u8 = 30;
pub const IORING_OP_PROVIDE_BUFFERS: u8 = 31;
pub const IORING_OP_REMOVE_BUFFERS: u8 = 32;
pub const IORING_OP_TEE: u8 = 33;
pub const IORING_OP_SHUTDOWN: u8 = 34;
pub const IORING_OP_RENAMEAT: u8 = 35;
pub const IORING_OP_UNLINKAT: u8 = 36;
pub const IORING_OP_MKDIRAT: u8 = 37;
pub const IORING_OP_SYMLINKAT: u8 = 38;
pub const IORING_OP_LINKAT: u8 = 39;
pub const IORING_OP_MSG_RING: u8 = 40;
pub const IORING_OP_FSETXATTR: u8 = 41;
pub const IORING_OP_SETXATTR: u8 = 42;
pub const IORING_OP_FGETXATTR: u8 = 43;
pub const IORING_OP_GETXATTR: u8 = 44;
pub const IORING_OP_SOCKET: u8 = 45;
pub const IORING_OP_URING_CMD: u8 = 46;
pub const IORING_OP_SEND_ZC: u8 = 47;
pub const IORING_OP_SENDMSG_ZC: u8 = 48;
pub const IORING_OP_WAITID: u8 = 49;
pub const IORING_OP_FUTEX_WAIT: u8 = 50;
pub const IORING_OP_FUTEX_WAKE: u8 = 51;
pub const IORING_OP_FUTEX_WAITV: u8 = 52;
pub const IORING_OP_FIXED_FD_INSTALL: u8 = 53;
pub const IORING_OP_FTRUNCATE: u8 = 54;
// Zxyphor extensions
pub const IORING_OP_ZXY_BATCH_IO: u8 = 128;
pub const IORING_OP_ZXY_ZERO_COPY_SPLICE: u8 = 129;
pub const IORING_OP_ZXY_GPU_SUBMIT: u8 = 130;
pub const IORING_OP_ZXY_NVME_PASSTHROUGH: u8 = 131;

// SQE flags
pub const IOSQE_FIXED_FILE: u32 = 1 << 0;
pub const IOSQE_IO_DRAIN: u32 = 1 << 1;
pub const IOSQE_IO_LINK: u32 = 1 << 2;
pub const IOSQE_IO_HARDLINK: u32 = 1 << 3;
pub const IOSQE_ASYNC: u32 = 1 << 4;
pub const IOSQE_BUFFER_SELECT: u32 = 1 << 5;
pub const IOSQE_CQE_SKIP_SUCCESS: u32 = 1 << 6;

#[repr(C)]
pub struct IoUringSqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off: u64,
    pub addr: u64,
    pub len: u32,
    pub op_flags: u32,
    pub user_data: u64,
    pub buf_index: u16,
    pub personality: u16,
    pub splice_fd_in: i32,
    pub addr3: u64,
    pub _pad: u64,
}

#[repr(C)]
pub struct IoUringCqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
    pub big_cqe: [u64; 2],  // For IORING_CQE_F_BIG_CQE
}

pub const IORING_CQE_F_BUFFER: u32 = 1 << 0;
pub const IORING_CQE_F_MORE: u32 = 1 << 1;
pub const IORING_CQE_F_SOCK_NONEMPTY: u32 = 1 << 2;
pub const IORING_CQE_F_NOTIF: u32 = 1 << 3;

// io_uring setup flags
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

pub struct IoUringContext {
    pub flags: u32,
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub sq_mask: u32,
    pub cq_mask: u32,
    // Ring state
    pub sq_head: AtomicU32,
    pub sq_tail: AtomicU32,
    pub cq_head: AtomicU32,
    pub cq_tail: AtomicU32,
    pub sq_dropped: AtomicU32,
    pub cq_overflow: AtomicU32,
    // Features
    pub features: u32,
    // SQPOLL
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    // Fixed files and buffers
    pub nr_user_files: u32,
    pub nr_user_bufs: u32,
    // Stats
    pub submit_count: AtomicU64,
    pub complete_count: AtomicU64,
    pub sq_full_count: AtomicU64,
    pub cq_full_count: AtomicU64,
}

pub const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;
pub const IORING_FEAT_NODROP: u32 = 1 << 1;
pub const IORING_FEAT_SUBMIT_STABLE: u32 = 1 << 2;
pub const IORING_FEAT_RW_CUR_POS: u32 = 1 << 3;
pub const IORING_FEAT_CUR_PERSONALITY: u32 = 1 << 4;
pub const IORING_FEAT_FAST_POLL: u32 = 1 << 5;
pub const IORING_FEAT_POLL_32BITS: u32 = 1 << 6;
pub const IORING_FEAT_SQPOLL_NONFIXED: u32 = 1 << 7;
pub const IORING_FEAT_EXT_ARG: u32 = 1 << 8;
pub const IORING_FEAT_NATIVE_WORKERS: u32 = 1 << 9;
pub const IORING_FEAT_RSRC_TAGS: u32 = 1 << 10;
pub const IORING_FEAT_CQE_SKIP: u32 = 1 << 11;
pub const IORING_FEAT_LINKED_FILE: u32 = 1 << 12;
pub const IORING_FEAT_REG_REG_RING: u32 = 1 << 13;

// ============================================================================
// epoll
// ============================================================================

pub const EPOLLIN: u32 = 0x00000001;
pub const EPOLLPRI: u32 = 0x00000002;
pub const EPOLLOUT: u32 = 0x00000004;
pub const EPOLLERR: u32 = 0x00000008;
pub const EPOLLHUP: u32 = 0x00000010;
pub const EPOLLNVAL: u32 = 0x00000020;
pub const EPOLLRDNORM: u32 = 0x00000040;
pub const EPOLLRDBAND: u32 = 0x00000080;
pub const EPOLLWRNORM: u32 = 0x00000100;
pub const EPOLLWRBAND: u32 = 0x00000200;
pub const EPOLLMSG: u32 = 0x00000400;
pub const EPOLLRDHUP: u32 = 0x00002000;
pub const EPOLLEXCLUSIVE: u32 = 1 << 28;
pub const EPOLLWAKEUP: u32 = 1 << 29;
pub const EPOLLONESHOT: u32 = 1 << 30;
pub const EPOLLET: u32 = 1 << 31;

pub const EPOLL_CTL_ADD: u32 = 1;
pub const EPOLL_CTL_DEL: u32 = 2;
pub const EPOLL_CTL_MOD: u32 = 3;

#[repr(C)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

pub struct EpollInstance {
    pub fds: [EpollItem; 1024],
    pub nr_fds: u32,
    pub ready_list: [u32; 1024],  // Indices into fds
    pub ready_count: AtomicU32,
    pub ovflist_count: u32,
    pub generation: AtomicU64,
}

pub struct EpollItem {
    pub fd: i32,
    pub event: EpollEvent,
    pub revents: AtomicU32,
    pub active: bool,
    pub ready: AtomicBool,
    pub nwait: AtomicU32,
}

// ============================================================================
// Pipe (with splice support)
// ============================================================================

pub const PIPE_BUF: usize = 4096;
pub const PIPE_DEF_BUFFERS: u32 = 16;
pub const PIPE_MAX_SIZE: u32 = 1048576;

pub struct PipeBuffer {
    pub page_pfn: u64,
    pub offset: u32,
    pub len: u32,
    pub flags: u32,
}

pub const PIPE_BUF_FLAG_LRU: u32 = 0x01;
pub const PIPE_BUF_FLAG_ATOMIC: u32 = 0x02;
pub const PIPE_BUF_FLAG_GIFT: u32 = 0x04;
pub const PIPE_BUF_FLAG_PACKET: u32 = 0x08;
pub const PIPE_BUF_FLAG_CAN_MERGE: u32 = 0x10;
pub const PIPE_BUF_FLAG_WHOLE: u32 = 0x20;

pub struct PipeInode {
    pub bufs: [PipeBuffer; 16],
    pub head: u32,
    pub tail: u32,
    pub max_usage: u32,
    pub ring_size: u32,
    pub nr_accounted: u32,
    pub readers: AtomicU32,
    pub writers: AtomicU32,
    pub files: AtomicU32,
    pub r_counter: AtomicU32,
    pub w_counter: AtomicU32,
    pub flags: u32,
    pub bytes_in_pipe: AtomicU64,
}

pub const O_PIPE_NONBLOCK: u32 = 0x800;
pub const O_PIPE_DIRECT: u32 = 0x4000;
pub const O_PIPE_NOTIFICATION: u32 = 0x8000;

// ============================================================================
// Unix Domain Socket
// ============================================================================

pub struct UnixSocket {
    pub sock_type: UnixSockType,
    pub state: UnixSockState,
    pub path: [u8; 108],    // sun_path from sockaddr_un
    pub path_len: u8,
    pub flags: u32,
    pub peer_socket_id: u64,
    pub backlog: u32,
    pub max_backlog: u32,
    pub pending_connections: [u64; 128],
    pub pending_count: u32,
    // Buffers
    pub recv_buf_size: u32,
    pub send_buf_size: u32,
    pub recv_buf_used: AtomicU32,
    pub send_buf_used: AtomicU32,
    // Credentials passing
    pub passcred: bool,
    pub passec: bool,       // Security label passing
    pub peer_pid: i32,
    pub peer_uid: u32,
    pub peer_gid: u32,
    // File descriptor passing (SCM_RIGHTS)
    pub scm_fds: [i32; 253],
    pub scm_fd_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnixSockType {
    Stream,
    Dgram,
    SeqPacket,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnixSockState {
    Unconnected,
    Connecting,
    Connected,
    Disconnecting,
    Listening,
}

// ============================================================================
// Netlink Socket
// ============================================================================

pub const NETLINK_ROUTE: u32 = 0;
pub const NETLINK_UNUSED: u32 = 1;
pub const NETLINK_USERSOCK: u32 = 2;
pub const NETLINK_FIREWALL: u32 = 3;
pub const NETLINK_SOCK_DIAG: u32 = 4;
pub const NETLINK_NFLOG: u32 = 5;
pub const NETLINK_XFRM: u32 = 6;
pub const NETLINK_SELINUX: u32 = 7;
pub const NETLINK_ISCSI: u32 = 8;
pub const NETLINK_AUDIT: u32 = 9;
pub const NETLINK_FIB_LOOKUP: u32 = 10;
pub const NETLINK_CONNECTOR: u32 = 11;
pub const NETLINK_NETFILTER: u32 = 12;
pub const NETLINK_IP6_FW: u32 = 13;
pub const NETLINK_DNRTMSG: u32 = 14;
pub const NETLINK_KOBJECT_UEVENT: u32 = 15;
pub const NETLINK_GENERIC: u32 = 16;
pub const NETLINK_SCSITRANSPORT: u32 = 18;
pub const NETLINK_ECRYPTFS: u32 = 19;
pub const NETLINK_RDMA: u32 = 20;
pub const NETLINK_CRYPTO: u32 = 21;
pub const NETLINK_SMC: u32 = 22;

pub struct NetlinkMessage {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
    pub payload: [u8; 4096],
    pub payload_len: u32,
}

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_ECHO: u16 = 0x08;
pub const NLM_F_DUMP_INTR: u16 = 0x10;
pub const NLM_F_DUMP_FILTERED: u16 = 0x20;
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
pub const NLM_F_ATOMIC: u16 = 0x400;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;

pub struct NetlinkSocket {
    pub protocol: u32,
    pub portid: u32,
    pub groups: u32,
    pub dst_portid: u32,
    pub dst_group: u32,
    pub flags: u32,
    pub cb_running: bool,
    pub bound: bool,
    pub recv_buf: [NetlinkMessage; 64],
    pub recv_count: AtomicU32,
}

// ============================================================================
// IPC Namespace
// ============================================================================

pub struct IpcNamespace {
    pub id: u64,
    // SysV IPC limits
    pub shm_ctlmax: u64,    // Max shared memory segment size
    pub shm_ctlall: u64,    // Max total shared memory
    pub shm_ctlmni: u32,    // Max shared memory segments
    pub shm_rmid_forced: bool,
    pub msg_ctlmax: u32,    // Max message size
    pub msg_ctlmnb: u32,    // Max bytes per queue
    pub msg_ctlmni: u32,    // Max message queues
    pub sem_ctls: [u32; 4], // SEMMSL, SEMMNS, SEMOPM, SEMMNI
    // POSIX mqueue limits
    pub mq_queues_max: u32,
    pub mq_msg_max: u32,
    pub mq_msgsize_max: u32,
    pub mq_msg_default: u32,
    pub mq_msgsize_default: u32,
    // Counters
    pub shm_tot: AtomicU64,
    pub msg_bytes: AtomicU64,
    pub msg_hdrs: AtomicU64,
}
