// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Process & Task Management (Rust)
// Namespaces, cgroups v2, seccomp, ptrace, capabilities, credentials

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

// ============================================================================
// Process Credentials
// ============================================================================

/// Kernel credential structure (like Linux struct cred)
#[derive(Clone, Copy)]
pub struct Credentials {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,     // Effective UID
    pub egid: u32,     // Effective GID
    pub suid: u32,     // Saved UID
    pub sgid: u32,     // Saved GID
    pub fsuid: u32,    // Filesystem UID
    pub fsgid: u32,    // Filesystem GID
    pub supplementary_gids: [32; u32],
    pub ngroups: u8,
    // Capabilities
    pub cap_inheritable: u64,
    pub cap_permitted: u64,
    pub cap_effective: u64,
    pub cap_bounding: u64,
    pub cap_ambient: u64,
    // Security
    pub securebits: u32,
    pub security_label: [64; u8],
    pub security_label_len: u8,
    // Keyring
    pub session_keyring: u32,
    pub process_keyring: u32,
    pub thread_keyring: u32,
    pub user_ns: u32,
}

/// POSIX Capabilities (Linux-compatible)
pub mod cap {
    pub const CAP_CHOWN: u64 = 1 << 0;
    pub const CAP_DAC_OVERRIDE: u64 = 1 << 1;
    pub const CAP_DAC_READ_SEARCH: u64 = 1 << 2;
    pub const CAP_FOWNER: u64 = 1 << 3;
    pub const CAP_FSETID: u64 = 1 << 4;
    pub const CAP_KILL: u64 = 1 << 5;
    pub const CAP_SETGID: u64 = 1 << 6;
    pub const CAP_SETUID: u64 = 1 << 7;
    pub const CAP_SETPCAP: u64 = 1 << 8;
    pub const CAP_LINUX_IMMUTABLE: u64 = 1 << 9;
    pub const CAP_NET_BIND_SERVICE: u64 = 1 << 10;
    pub const CAP_NET_BROADCAST: u64 = 1 << 11;
    pub const CAP_NET_ADMIN: u64 = 1 << 12;
    pub const CAP_NET_RAW: u64 = 1 << 13;
    pub const CAP_IPC_LOCK: u64 = 1 << 14;
    pub const CAP_IPC_OWNER: u64 = 1 << 15;
    pub const CAP_SYS_MODULE: u64 = 1 << 16;
    pub const CAP_SYS_RAWIO: u64 = 1 << 17;
    pub const CAP_SYS_CHROOT: u64 = 1 << 18;
    pub const CAP_SYS_PTRACE: u64 = 1 << 19;
    pub const CAP_SYS_PACCT: u64 = 1 << 20;
    pub const CAP_SYS_ADMIN: u64 = 1 << 21;
    pub const CAP_SYS_BOOT: u64 = 1 << 22;
    pub const CAP_SYS_NICE: u64 = 1 << 23;
    pub const CAP_SYS_RESOURCE: u64 = 1 << 24;
    pub const CAP_SYS_TIME: u64 = 1 << 25;
    pub const CAP_SYS_TTY_CONFIG: u64 = 1 << 26;
    pub const CAP_MKNOD: u64 = 1 << 27;
    pub const CAP_LEASE: u64 = 1 << 28;
    pub const CAP_AUDIT_WRITE: u64 = 1 << 29;
    pub const CAP_AUDIT_CONTROL: u64 = 1 << 30;
    pub const CAP_SETFCAP: u64 = 1 << 31;
    pub const CAP_MAC_OVERRIDE: u64 = 1 << 32;
    pub const CAP_MAC_ADMIN: u64 = 1 << 33;
    pub const CAP_SYSLOG: u64 = 1 << 34;
    pub const CAP_WAKE_ALARM: u64 = 1 << 35;
    pub const CAP_BLOCK_SUSPEND: u64 = 1 << 36;
    pub const CAP_AUDIT_READ: u64 = 1 << 37;
    pub const CAP_PERFMON: u64 = 1 << 38;
    pub const CAP_BPF: u64 = 1 << 39;
    pub const CAP_CHECKPOINT_RESTORE: u64 = 1 << 40;
    // Zxyphor extensions
    pub const CAP_ZXY_GPU: u64 = 1 << 48;
    pub const CAP_ZXY_HYPERVISOR: u64 = 1 << 49;
    pub const CAP_ZXY_HOTPLUG: u64 = 1 << 50;
    pub const CAP_ZXY_FIRMWARE: u64 = 1 << 51;

    pub const CAP_ALL: u64 = u64::MAX;
    pub const CAP_EMPTY: u64 = 0;
}

impl Credentials {
    pub fn root() -> Self {
        Credentials {
            uid: 0, gid: 0, euid: 0, egid: 0,
            suid: 0, sgid: 0, fsuid: 0, fsgid: 0,
            supplementary_gids: [0; 32],
            ngroups: 0,
            cap_inheritable: cap::CAP_ALL,
            cap_permitted: cap::CAP_ALL,
            cap_effective: cap::CAP_ALL,
            cap_bounding: cap::CAP_ALL,
            cap_ambient: cap::CAP_EMPTY,
            securebits: 0,
            security_label: [0; 64],
            security_label_len: 0,
            session_keyring: 0,
            process_keyring: 0,
            thread_keyring: 0,
            user_ns: 0,
        }
    }

    pub fn unprivileged(uid: u32, gid: u32) -> Self {
        Credentials {
            uid, gid, euid: uid, egid: gid,
            suid: uid, sgid: gid, fsuid: uid, fsgid: gid,
            supplementary_gids: [0; 32],
            ngroups: 0,
            cap_inheritable: cap::CAP_EMPTY,
            cap_permitted: cap::CAP_EMPTY,
            cap_effective: cap::CAP_EMPTY,
            cap_bounding: cap::CAP_ALL,
            cap_ambient: cap::CAP_EMPTY,
            securebits: 0,
            security_label: [0; 64],
            security_label_len: 0,
            session_keyring: 0,
            process_keyring: 0,
            thread_keyring: 0,
            user_ns: 0,
        }
    }

    pub fn has_cap(&self, cap_bit: u64) -> bool {
        self.cap_effective & cap_bit != 0
    }

    pub fn is_root(&self) -> bool {
        self.euid == 0
    }

    pub fn in_group(&self, gid: u32) -> bool {
        if self.egid == gid || self.gid == gid { return true; }
        for i in 0..self.ngroups as usize {
            if self.supplementary_gids[i] == gid { return true; }
        }
        false
    }
}

// ============================================================================
// Namespace
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum NsType {
    Mnt = 0x00020000,     // CLONE_NEWNS
    Uts = 0x04000000,     // CLONE_NEWUTS
    Ipc = 0x08000000,     // CLONE_NEWIPC
    User = 0x10000000,    // CLONE_NEWUSER
    Pid = 0x20000000,     // CLONE_NEWPID
    Net = 0x40000000,     // CLONE_NEWNET
    Cgroup = 0x02000000,  // CLONE_NEWCGROUP
    Time = 0x00000080,    // CLONE_NEWTIME
}

pub struct Namespace {
    pub ns_type: NsType,
    pub id: u32,
    pub parent_id: u32,
    pub owner_uid: u32,
    pub ref_count: AtomicU32,
    pub level: u8,        // Nesting level
    pub flags: u32,
}

pub struct NsSet {
    pub mnt_ns: u32,
    pub uts_ns: u32,
    pub ipc_ns: u32,
    pub user_ns: u32,
    pub pid_ns: u32,
    pub net_ns: u32,
    pub cgroup_ns: u32,
    pub time_ns: u32,
}

impl NsSet {
    pub fn init_ns() -> Self {
        NsSet {
            mnt_ns: 1,
            uts_ns: 1,
            ipc_ns: 1,
            user_ns: 1,
            pid_ns: 1,
            net_ns: 1,
            cgroup_ns: 1,
            time_ns: 1,
        }
    }
}

/// UTS namespace data
pub struct UtsNamespace {
    pub sysname: [65; u8],
    pub nodename: [65; u8],
    pub release: [65; u8],
    pub version: [65; u8],
    pub machine: [65; u8],
    pub domainname: [65; u8],
}

impl UtsNamespace {
    pub fn default_init() -> Self {
        let mut uts = UtsNamespace {
            sysname: [0; 65],
            nodename: [0; 65],
            release: [0; 65],
            version: [0; 65],
            machine: [0; 65],
            domainname: [0; 65],
        };
        let name = b"Zxyphor";
        uts.sysname[..name.len()].copy_from_slice(name);
        let release = b"1.0.0-zxy";
        uts.release[..release.len()].copy_from_slice(release);
        let machine = b"x86_64";
        uts.machine[..machine.len()].copy_from_slice(machine);
        uts
    }
}

// ============================================================================
// Cgroups v2
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CgroupController {
    Cpu,
    CpuSet,
    Memory,
    Io,
    Pids,
    Rdma,
    HugeTlb,
    Misc,
    // Zxyphor extensions
    Gpu,
    Network,
}

pub struct CgroupV2 {
    pub id: u64,
    pub parent_id: u64,
    pub name: [128; u8],
    pub name_len: u8,
    pub level: u8,
    pub controllers: u32,    // Bitmask of enabled controllers
    pub subtree_control: u32,
    pub populated: AtomicBool,
    pub frozen: AtomicBool,
    // CPU controller
    pub cpu_weight: u32,          // 1-10000, default 100
    pub cpu_weight_nice: i8,      // -20 to 19
    pub cpu_max_quota_us: i64,    // -1 = max
    pub cpu_max_period_us: u64,   // default 100000
    pub cpu_burst_us: u64,
    // CPU stats
    pub cpu_usage_usec: AtomicU64,
    pub cpu_user_usec: AtomicU64,
    pub cpu_system_usec: AtomicU64,
    pub nr_periods: AtomicU64,
    pub nr_throttled: AtomicU64,
    pub throttled_usec: AtomicU64,
    // Memory controller
    pub memory_min: u64,          // Minimum guarantee
    pub memory_low: u64,          // Best-effort low boundary
    pub memory_high: u64,         // Throttle above
    pub memory_max: u64,          // Hard limit (OOM)
    pub memory_swap_max: u64,
    pub memory_current: AtomicU64,
    pub memory_swap_current: AtomicU64,
    pub memory_peak: AtomicU64,
    pub memory_oom_group: bool,
    // IO controller
    pub io_weight: u32,           // 1-10000, default 100
    pub io_max: [8; IoMax],       // Per-device limits
    pub io_max_count: u8,
    // PIDs controller
    pub pids_max: u64,            // Max processes
    pub pids_current: AtomicU64,
    // Process tracking
    pub nr_procs: AtomicU32,
    pub nr_dying_descendants: AtomicU32,
    // PSI (Pressure Stall Information)
    pub psi_some_total_us: AtomicU64, // microseconds of partial stall
    pub psi_full_total_us: AtomicU64, // microseconds of complete stall
}

#[derive(Clone, Copy)]
pub struct IoMax {
    pub major: u32,
    pub minor: u32,
    pub rbps: u64,    // Read bytes/sec, 0 = unlimited
    pub wbps: u64,    // Write bytes/sec
    pub riops: u32,   // Read ops/sec
    pub wiops: u32,   // Write ops/sec
}

impl CgroupV2 {
    pub fn new(id: u64, parent_id: u64) -> Self {
        CgroupV2 {
            id,
            parent_id,
            name: [0; 128],
            name_len: 0,
            level: 0,
            controllers: 0,
            subtree_control: 0,
            populated: AtomicBool::new(false),
            frozen: AtomicBool::new(false),
            cpu_weight: 100,
            cpu_weight_nice: 0,
            cpu_max_quota_us: -1,
            cpu_max_period_us: 100_000,
            cpu_burst_us: 0,
            cpu_usage_usec: AtomicU64::new(0),
            cpu_user_usec: AtomicU64::new(0),
            cpu_system_usec: AtomicU64::new(0),
            nr_periods: AtomicU64::new(0),
            nr_throttled: AtomicU64::new(0),
            throttled_usec: AtomicU64::new(0),
            memory_min: 0,
            memory_low: 0,
            memory_high: u64::MAX,
            memory_max: u64::MAX,
            memory_swap_max: u64::MAX,
            memory_current: AtomicU64::new(0),
            memory_swap_current: AtomicU64::new(0),
            memory_peak: AtomicU64::new(0),
            memory_oom_group: false,
            io_weight: 100,
            io_max: [IoMax { major: 0, minor: 0, rbps: 0, wbps: 0, riops: 0, wiops: 0 }; 8],
            io_max_count: 0,
            pids_max: u64::MAX,
            pids_current: AtomicU64::new(0),
            nr_procs: AtomicU32::new(0),
            nr_dying_descendants: AtomicU32::new(0),
            psi_some_total_us: AtomicU64::new(0),
            psi_full_total_us: AtomicU64::new(0),
        }
    }

    pub fn charge_memory(&self, bytes: u64) -> CgroupChargeResult {
        let current = self.memory_current.fetch_add(bytes, Ordering::Relaxed);
        let new_total = current + bytes;

        // Update peak
        let mut peak = self.memory_peak.load(Ordering::Relaxed);
        while new_total > peak {
            match self.memory_peak.compare_exchange_weak(
                peak, new_total, Ordering::Relaxed, Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }

        if new_total > self.memory_max {
            self.memory_current.fetch_sub(bytes, Ordering::Relaxed);
            return CgroupChargeResult::OomKill;
        }
        if new_total > self.memory_high {
            return CgroupChargeResult::Throttle;
        }
        CgroupChargeResult::Ok
    }

    pub fn uncharge_memory(&self, bytes: u64) {
        self.memory_current.fetch_sub(bytes, Ordering::Relaxed);
    }

    pub fn try_alloc_pid(&self) -> bool {
        let current = self.pids_current.load(Ordering::Relaxed);
        if current >= self.pids_max {
            return false;
        }
        self.pids_current.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn free_pid(&self) {
        self.pids_current.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CgroupChargeResult {
    Ok,
    Throttle,
    OomKill,
}

// ============================================================================
// Seccomp-BPF
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum SeccompAction {
    KillProcess = 0x80000000,
    KillThread = 0x00000000,
    Trap = 0x00030000,
    Errno(u16) = 0x00050000,
    UserNotif = 0x7FC00000,
    Trace(u16) = 0x7FF00000,
    Log = 0x7FFC0000,
    Allow = 0x7FFF0000,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SeccompData {
    pub nr: u32,             // System call number
    pub arch: u32,           // Architecture (AUDIT_ARCH_*)
    pub instruction_pointer: u64,
    pub args: [6; u64],      // System call arguments
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,    // Jump if true
    pub jf: u8,    // Jump if false
    pub k: u32,    // Immediate value
}

pub mod bpf {
    // BPF instruction classes
    pub const BPF_LD: u16 = 0x00;
    pub const BPF_LDX: u16 = 0x01;
    pub const BPF_ST: u16 = 0x02;
    pub const BPF_STX: u16 = 0x03;
    pub const BPF_ALU: u16 = 0x04;
    pub const BPF_JMP: u16 = 0x05;
    pub const BPF_RET: u16 = 0x06;
    pub const BPF_MISC: u16 = 0x07;
    // Size
    pub const BPF_W: u16 = 0x00;
    pub const BPF_H: u16 = 0x08;
    pub const BPF_B: u16 = 0x10;
    // Mode
    pub const BPF_IMM: u16 = 0x00;
    pub const BPF_ABS: u16 = 0x20;
    pub const BPF_IND: u16 = 0x40;
    pub const BPF_MEM: u16 = 0x60;
    // ALU ops
    pub const BPF_ADD: u16 = 0x00;
    pub const BPF_SUB: u16 = 0x10;
    pub const BPF_AND: u16 = 0x50;
    pub const BPF_OR: u16 = 0x40;
    pub const BPF_XOR: u16 = 0xA0;
    // Jump ops
    pub const BPF_JA: u16 = 0x00;
    pub const BPF_JEQ: u16 = 0x10;
    pub const BPF_JGT: u16 = 0x20;
    pub const BPF_JGE: u16 = 0x30;
    pub const BPF_JSET: u16 = 0x40;
    // Source
    pub const BPF_K: u16 = 0x00;
    pub const BPF_X: u16 = 0x08;
}

pub struct SeccompFilter {
    pub instructions: [256; BpfInsn],
    pub num_insns: u16,
    pub flags: u32,
    pub ref_count: AtomicU32,
}

impl SeccompFilter {
    pub fn new() -> Self {
        SeccompFilter {
            instructions: [BpfInsn { code: 0, jt: 0, jf: 0, k: 0 }; 256],
            num_insns: 0,
            flags: 0,
            ref_count: AtomicU32::new(1),
        }
    }

    /// Execute the BPF filter against seccomp data
    pub fn evaluate(&self, data: &SeccompData) -> u32 {
        let mut a: u32 = 0;  // Accumulator
        let mut x: u32 = 0;  // Index register
        let mut mem = [0u32; 16]; // Scratch memory
        let mut pc: usize = 0;

        let data_bytes = unsafe {
            core::slice::from_raw_parts(
                data as *const SeccompData as *const u8,
                core::mem::size_of::<SeccompData>()
            )
        };

        while pc < self.num_insns as usize {
            let insn = &self.instructions[pc];
            let class = insn.code & 0x07;

            match class {
                0x00 => { // BPF_LD
                    let mode = insn.code & 0xE0;
                    let size = insn.code & 0x18;
                    match mode {
                        0x00 => a = insn.k, // IMM
                        0x20 => { // ABS
                            let off = insn.k as usize;
                            match size {
                                0x00 => { // W
                                    if off + 4 <= data_bytes.len() {
                                        a = u32::from_ne_bytes([
                                            data_bytes[off], data_bytes[off+1],
                                            data_bytes[off+2], data_bytes[off+3],
                                        ]);
                                    }
                                }
                                0x08 => { // H
                                    if off + 2 <= data_bytes.len() {
                                        a = u16::from_ne_bytes([
                                            data_bytes[off], data_bytes[off+1],
                                        ]) as u32;
                                    }
                                }
                                0x10 => { // B
                                    if off < data_bytes.len() {
                                        a = data_bytes[off] as u32;
                                    }
                                }
                                _ => {}
                            }
                        }
                        0x60 => { // MEM
                            let idx = insn.k as usize;
                            if idx < 16 { a = mem[idx]; }
                        }
                        _ => {}
                    }
                }
                0x04 => { // BPF_ALU
                    let op = insn.code & 0xF0;
                    let src = if insn.code & 0x08 != 0 { x } else { insn.k };
                    match op {
                        0x00 => a = a.wrapping_add(src),
                        0x10 => a = a.wrapping_sub(src),
                        0x50 => a &= src,
                        0x40 => a |= src,
                        0xA0 => a ^= src,
                        _ => {}
                    }
                }
                0x05 => { // BPF_JMP
                    let op = insn.code & 0xF0;
                    let src = if insn.code & 0x08 != 0 { x } else { insn.k };
                    let jump = match op {
                        0x00 => { pc += insn.k as usize; continue; } // JA
                        0x10 => a == src,    // JEQ
                        0x20 => a > src,     // JGT
                        0x30 => a >= src,    // JGE
                        0x40 => a & src != 0, // JSET
                        _ => false,
                    };
                    pc += 1 + if jump { insn.jt as usize } else { insn.jf as usize };
                    continue;
                }
                0x06 => { // BPF_RET
                    return if insn.code & 0x08 != 0 { a } else { insn.k };
                }
                0x02 => { // BPF_ST
                    let idx = insn.k as usize;
                    if idx < 16 { mem[idx] = a; }
                }
                0x03 => { // BPF_STX
                    let idx = insn.k as usize;
                    if idx < 16 { mem[idx] = x; }
                }
                0x07 => { // BPF_MISC
                    if insn.code & 0x08 == 0 { x = a; } else { a = x; }
                }
                _ => {}
            }
            pc += 1;
        }
        0 // Default: KILL
    }
}

// ============================================================================
// Resource Limits (rlimit)
// ============================================================================

#[derive(Clone, Copy)]
pub struct Rlimit {
    pub cur: u64,    // Soft limit
    pub max: u64,    // Hard limit
}

pub const RLIMIT_CPU: usize = 0;
pub const RLIMIT_FSIZE: usize = 1;
pub const RLIMIT_DATA: usize = 2;
pub const RLIMIT_STACK: usize = 3;
pub const RLIMIT_CORE: usize = 4;
pub const RLIMIT_RSS: usize = 5;
pub const RLIMIT_NPROC: usize = 6;
pub const RLIMIT_NOFILE: usize = 7;
pub const RLIMIT_MEMLOCK: usize = 8;
pub const RLIMIT_AS: usize = 9;
pub const RLIMIT_LOCKS: usize = 10;
pub const RLIMIT_SIGPENDING: usize = 11;
pub const RLIMIT_MSGQUEUE: usize = 12;
pub const RLIMIT_NICE: usize = 13;
pub const RLIMIT_RTPRIO: usize = 14;
pub const RLIMIT_RTTIME: usize = 15;
pub const RLIM_NLIMITS: usize = 16;
pub const RLIM_INFINITY: u64 = u64::MAX;

pub struct RlimitSet {
    pub limits: [RLIM_NLIMITS; Rlimit],
}

impl RlimitSet {
    pub fn default_init() -> Self {
        let inf = RLIM_INFINITY;
        RlimitSet {
            limits: [
                Rlimit { cur: inf, max: inf },              // CPU
                Rlimit { cur: inf, max: inf },              // FSIZE
                Rlimit { cur: inf, max: inf },              // DATA
                Rlimit { cur: 8 * 1024 * 1024, max: inf }, // STACK (8MB)
                Rlimit { cur: 0, max: inf },                // CORE
                Rlimit { cur: inf, max: inf },              // RSS
                Rlimit { cur: 63704, max: 63704 },         // NPROC
                Rlimit { cur: 1024, max: 1048576 },        // NOFILE
                Rlimit { cur: 65536, max: 65536 },         // MEMLOCK
                Rlimit { cur: inf, max: inf },              // AS
                Rlimit { cur: inf, max: inf },              // LOCKS
                Rlimit { cur: 63704, max: 63704 },         // SIGPENDING
                Rlimit { cur: 819200, max: 819200 },       // MSGQUEUE
                Rlimit { cur: 0, max: 0 },                 // NICE
                Rlimit { cur: 0, max: 0 },                 // RTPRIO
                Rlimit { cur: inf, max: inf },              // RTTIME
            ]
        }
    }
}

// ============================================================================
// Process Accounting & Stats
// ============================================================================

pub struct TaskStats {
    // CPU
    pub utime_ns: AtomicU64,
    pub stime_ns: AtomicU64,
    pub real_start_time_ns: u64,
    pub start_time_ns: u64,
    pub nvcsw: AtomicU64,     // Voluntary context switches
    pub nivcsw: AtomicU64,    // Involuntary context switches
    // Memory
    pub vsize_bytes: AtomicU64,
    pub rss_pages: AtomicU64,
    pub rss_peak_pages: u64,
    pub min_flt: AtomicU64,   // Minor page faults
    pub maj_flt: AtomicU64,   // Major page faults
    // IO
    pub read_bytes: AtomicU64,
    pub write_bytes: AtomicU64,
    pub read_syscalls: AtomicU64,
    pub write_syscalls: AtomicU64,
    pub cancelled_write_bytes: AtomicU64,
    // Scheduling
    pub blkio_delay_ns: AtomicU64,
    pub swapin_delay_ns: AtomicU64,
    pub freepages_delay_ns: AtomicU64,
    pub thrashing_delay_ns: AtomicU64,
    pub compact_delay_ns: AtomicU64,
}

impl TaskStats {
    pub fn new(start_ns: u64) -> Self {
        TaskStats {
            utime_ns: AtomicU64::new(0),
            stime_ns: AtomicU64::new(0),
            real_start_time_ns: start_ns,
            start_time_ns: start_ns,
            nvcsw: AtomicU64::new(0),
            nivcsw: AtomicU64::new(0),
            vsize_bytes: AtomicU64::new(0),
            rss_pages: AtomicU64::new(0),
            rss_peak_pages: 0,
            min_flt: AtomicU64::new(0),
            maj_flt: AtomicU64::new(0),
            read_bytes: AtomicU64::new(0),
            write_bytes: AtomicU64::new(0),
            read_syscalls: AtomicU64::new(0),
            write_syscalls: AtomicU64::new(0),
            cancelled_write_bytes: AtomicU64::new(0),
            blkio_delay_ns: AtomicU64::new(0),
            swapin_delay_ns: AtomicU64::new(0),
            freepages_delay_ns: AtomicU64::new(0),
            thrashing_delay_ns: AtomicU64::new(0),
            compact_delay_ns: AtomicU64::new(0),
        }
    }

    pub fn cpu_total_ns(&self) -> u64 {
        self.utime_ns.load(Ordering::Relaxed) + self.stime_ns.load(Ordering::Relaxed)
    }
}
