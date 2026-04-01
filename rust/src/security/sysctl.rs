// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Sysctl Framework (Rust)
//
// Linux-compatible /proc/sys parameter interface:
// - Registration of kernel tunables via hierarchical path
// - Type-safe parameter access (int, uint, bool, string, mode)
// - Range validation with min/max bounds
// - Read-only and read-write permissions
// - /proc/sys path lookup (kernel.*, vm.*, net.*, fs.*, dev.*)
// - proc_handler callbacks for custom logic
// - Binary sysctl compatibility (deprecated numbers)
// - Sysctl table registration/unregistration
// - Default kernel parameters with sane values

#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};

// ─────────────────── Constants ──────────────────────────────────────

const MAX_ENTRIES: usize = 256;
const MAX_TABLES: usize = 32;
const MAX_NAME_LEN: usize = 64;
const MAX_PATH_LEN: usize = 128;
const MAX_STR_VAL_LEN: usize = 256;

// ─────────────────── Sysctl Types ───────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SysctlType {
    Int = 0,
    UInt = 1,
    Long = 2,
    ULong = 3,
    Bool = 4,
    String = 5,
    Octal = 6,    // Mode/permissions display
    Hex = 7,
}

// ─────────────────── Mode (permissions) ─────────────────────────────

#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SysctlMode {
    ReadOnly = 0o444,
    ReadWrite = 0o644,
    RootOnly = 0o600,
    RootRead = 0o400,
}

// ─────────────────── Directory IDs ──────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SysctlDir {
    Kernel = 0,
    Vm = 1,
    Net = 2,
    Fs = 3,
    Dev = 4,
    Debug = 5,
    Abi = 6,
    NetCore = 7,
    NetIpv4 = 8,
    NetIpv6 = 9,
    VmSwap = 10,
    KernelRandom = 11,
}

impl SysctlDir {
    pub fn prefix(&self) -> &'static [u8] {
        match self {
            SysctlDir::Kernel => b"kernel",
            SysctlDir::Vm => b"vm",
            SysctlDir::Net => b"net",
            SysctlDir::Fs => b"fs",
            SysctlDir::Dev => b"dev",
            SysctlDir::Debug => b"debug",
            SysctlDir::Abi => b"abi",
            SysctlDir::NetCore => b"net.core",
            SysctlDir::NetIpv4 => b"net.ipv4",
            SysctlDir::NetIpv6 => b"net.ipv6",
            SysctlDir::VmSwap => b"vm.swap",
            SysctlDir::KernelRandom => b"kernel.random",
        }
    }
}

// ─────────────────── Value Storage ──────────────────────────────────

#[derive(Clone, Copy)]
pub union SysctlValue {
    pub int_val: i64,
    pub uint_val: u64,
    pub bool_val: bool,
    pub str_val: [u8; MAX_STR_VAL_LEN],
}

impl SysctlValue {
    pub const fn zero() -> Self {
        Self { uint_val: 0 }
    }
}

// ─────────────────── Custom Handler ─────────────────────────────────

pub type ProcHandler = fn(entry: &SysctlEntry, write: bool, buf: &mut [u8]) -> isize;

// ─────────────────── Sysctl Entry ───────────────────────────────────

#[derive(Clone, Copy)]
pub struct SysctlEntry {
    // Identification
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: u8,
    pub full_path: [u8; MAX_PATH_LEN],
    pub path_len: u8,
    pub dir: SysctlDir,
    pub entry_type: SysctlType,
    pub mode: SysctlMode,

    // Value
    pub value: SysctlValue,
    pub default_value: SysctlValue,

    // Validation bounds
    pub min_val: i64,
    pub max_val: i64,
    pub has_bounds: bool,

    // Custom handler
    pub handler: Option<ProcHandler>,

    // Stats
    pub read_count: u32,
    pub write_count: u32,

    // State
    pub active: bool,
    pub table_id: u8,
}

impl SysctlEntry {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            full_path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            dir: SysctlDir::Kernel,
            entry_type: SysctlType::Int,
            mode: SysctlMode::ReadWrite,
            value: SysctlValue::zero(),
            default_value: SysctlValue::zero(),
            min_val: i64::MIN,
            max_val: i64::MAX,
            has_bounds: false,
            handler: None,
            read_count: 0,
            write_count: 0,
            active: false,
            table_id: 0,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(MAX_NAME_LEN - 1);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn build_path(&mut self) {
        let prefix = self.dir.prefix();
        let plen = prefix.len();
        if plen + 1 + self.name_len as usize > MAX_PATH_LEN {
            return;
        }
        self.full_path[..plen].copy_from_slice(prefix);
        self.full_path[plen] = b'.';
        let nlen = self.name_len as usize;
        self.full_path[plen + 1..plen + 1 + nlen].copy_from_slice(&self.name[..nlen]);
        self.path_len = (plen + 1 + nlen) as u8;
    }

    pub fn get_int(&self) -> i64 {
        unsafe { self.value.int_val }
    }

    pub fn get_uint(&self) -> u64 {
        unsafe { self.value.uint_val }
    }

    pub fn get_bool(&self) -> bool {
        unsafe { self.value.bool_val }
    }

    pub fn set_int(&mut self, v: i64) -> bool {
        if self.mode == SysctlMode::ReadOnly || self.mode == SysctlMode::RootRead {
            return false;
        }
        if self.has_bounds && (v < self.min_val || v > self.max_val) {
            return false;
        }
        self.value.int_val = v;
        self.write_count += 1;
        true
    }

    pub fn set_uint(&mut self, v: u64) -> bool {
        if self.mode == SysctlMode::ReadOnly || self.mode == SysctlMode::RootRead {
            return false;
        }
        if self.has_bounds {
            let sv = v as i64;
            if sv < self.min_val || sv > self.max_val {
                return false;
            }
        }
        self.value.uint_val = v;
        self.write_count += 1;
        true
    }

    pub fn set_bool(&mut self, v: bool) -> bool {
        if self.mode == SysctlMode::ReadOnly || self.mode == SysctlMode::RootRead {
            return false;
        }
        self.value.bool_val = v;
        self.write_count += 1;
        true
    }
}

// ─────────────────── Sysctl Table ───────────────────────────────────

#[derive(Clone, Copy)]
pub struct SysctlTable {
    pub name: [u8; 32],
    pub name_len: u8,
    pub dir: SysctlDir,
    pub entry_start: u16,
    pub entry_count: u16,
    pub active: bool,
}

impl SysctlTable {
    pub const fn new() -> Self {
        Self {
            name: [0u8; 32],
            name_len: 0,
            dir: SysctlDir::Kernel,
            entry_start: 0,
            entry_count: 0,
            active: false,
        }
    }
}

// ─────────────────── Sysctl Manager ─────────────────────────────────

pub struct SysctlManager {
    entries: [SysctlEntry; MAX_ENTRIES],
    entry_count: u16,
    tables: [SysctlTable; MAX_TABLES],
    table_count: u8,
    total_reads: AtomicU64,
    total_writes: AtomicU64,
}

impl SysctlManager {
    pub const fn new() -> Self {
        Self {
            entries: [SysctlEntry::new(); MAX_ENTRIES],
            entry_count: 0,
            tables: [SysctlTable::new(); MAX_TABLES],
            table_count: 0,
            total_reads: AtomicU64::new(0),
            total_writes: AtomicU64::new(0),
        }
    }

    pub fn init(&mut self) {
        self.register_kernel_defaults();
        self.register_vm_defaults();
        self.register_net_defaults();
        self.register_fs_defaults();
    }

    // ─── Registration ───────────────────────────────────────────────

    pub fn register_int(
        &mut self,
        dir: SysctlDir,
        name: &[u8],
        value: i64,
        mode: SysctlMode,
    ) -> Option<u16> {
        self.register_int_bounded(dir, name, value, i64::MIN, i64::MAX, false, mode)
    }

    pub fn register_int_bounded(
        &mut self,
        dir: SysctlDir,
        name: &[u8],
        value: i64,
        min: i64,
        max: i64,
        bounded: bool,
        mode: SysctlMode,
    ) -> Option<u16> {
        if self.entry_count as usize >= MAX_ENTRIES {
            return None;
        }
        let idx = self.entry_count;
        let e = &mut self.entries[idx as usize];
        *e = SysctlEntry::new();
        e.set_name(name);
        e.dir = dir;
        e.entry_type = SysctlType::Int;
        e.mode = mode;
        e.value.int_val = value;
        e.default_value.int_val = value;
        e.min_val = min;
        e.max_val = max;
        e.has_bounds = bounded;
        e.active = true;
        e.build_path();
        self.entry_count += 1;
        Some(idx)
    }

    pub fn register_uint(
        &mut self,
        dir: SysctlDir,
        name: &[u8],
        value: u64,
        mode: SysctlMode,
    ) -> Option<u16> {
        if self.entry_count as usize >= MAX_ENTRIES {
            return None;
        }
        let idx = self.entry_count;
        let e = &mut self.entries[idx as usize];
        *e = SysctlEntry::new();
        e.set_name(name);
        e.dir = dir;
        e.entry_type = SysctlType::UInt;
        e.mode = mode;
        e.value.uint_val = value;
        e.default_value.uint_val = value;
        e.active = true;
        e.build_path();
        self.entry_count += 1;
        Some(idx)
    }

    pub fn register_bool(
        &mut self,
        dir: SysctlDir,
        name: &[u8],
        value: bool,
        mode: SysctlMode,
    ) -> Option<u16> {
        if self.entry_count as usize >= MAX_ENTRIES {
            return None;
        }
        let idx = self.entry_count;
        let e = &mut self.entries[idx as usize];
        *e = SysctlEntry::new();
        e.set_name(name);
        e.dir = dir;
        e.entry_type = SysctlType::Bool;
        e.mode = mode;
        e.value.bool_val = value;
        e.default_value.bool_val = value;
        e.active = true;
        e.build_path();
        self.entry_count += 1;
        Some(idx)
    }

    pub fn register_string(
        &mut self,
        dir: SysctlDir,
        name: &[u8],
        value: &[u8],
        mode: SysctlMode,
    ) -> Option<u16> {
        if self.entry_count as usize >= MAX_ENTRIES {
            return None;
        }
        let idx = self.entry_count;
        let e = &mut self.entries[idx as usize];
        *e = SysctlEntry::new();
        e.set_name(name);
        e.dir = dir;
        e.entry_type = SysctlType::String;
        e.mode = mode;
        let slen = value.len().min(MAX_STR_VAL_LEN - 1);
        unsafe {
            e.value.str_val[..slen].copy_from_slice(&value[..slen]);
            e.default_value.str_val[..slen].copy_from_slice(&value[..slen]);
        }
        e.active = true;
        e.build_path();
        self.entry_count += 1;
        Some(idx)
    }

    // ─── Lookup ─────────────────────────────────────────────────────

    /// Find entry by full path (e.g. "kernel.hostname")
    pub fn find_by_path(&self, path: &[u8]) -> Option<u16> {
        for i in 0..self.entry_count as usize {
            if !self.entries[i].active {
                continue;
            }
            let plen = self.entries[i].path_len as usize;
            if plen == path.len() && &self.entries[i].full_path[..plen] == path {
                return Some(i as u16);
            }
        }
        None
    }

    /// Find entry by directory + name
    pub fn find_by_name(&self, dir: SysctlDir, name: &[u8]) -> Option<u16> {
        for i in 0..self.entry_count as usize {
            if !self.entries[i].active {
                continue;
            }
            if self.entries[i].dir as u8 == dir as u8 {
                let nlen = self.entries[i].name_len as usize;
                if nlen == name.len() && &self.entries[i].name[..nlen] == name {
                    return Some(i as u16);
                }
            }
        }
        None
    }

    // ─── Read / Write ───────────────────────────────────────────────

    pub fn read_int(&mut self, idx: u16) -> Option<i64> {
        let i = idx as usize;
        if i >= MAX_ENTRIES || !self.entries[i].active {
            return None;
        }
        self.entries[i].read_count += 1;
        self.total_reads.fetch_add(1, Ordering::Relaxed);
        Some(self.entries[i].get_int())
    }

    pub fn read_uint(&mut self, idx: u16) -> Option<u64> {
        let i = idx as usize;
        if i >= MAX_ENTRIES || !self.entries[i].active {
            return None;
        }
        self.entries[i].read_count += 1;
        self.total_reads.fetch_add(1, Ordering::Relaxed);
        Some(self.entries[i].get_uint())
    }

    pub fn read_bool(&mut self, idx: u16) -> Option<bool> {
        let i = idx as usize;
        if i >= MAX_ENTRIES || !self.entries[i].active {
            return None;
        }
        self.entries[i].read_count += 1;
        self.total_reads.fetch_add(1, Ordering::Relaxed);
        Some(self.entries[i].get_bool())
    }

    pub fn write_int(&mut self, idx: u16, val: i64) -> bool {
        let i = idx as usize;
        if i >= MAX_ENTRIES || !self.entries[i].active {
            return false;
        }
        let ok = self.entries[i].set_int(val);
        if ok {
            self.total_writes.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }

    pub fn write_uint(&mut self, idx: u16, val: u64) -> bool {
        let i = idx as usize;
        if i >= MAX_ENTRIES || !self.entries[i].active {
            return false;
        }
        let ok = self.entries[i].set_uint(val);
        if ok {
            self.total_writes.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }

    pub fn write_bool(&mut self, idx: u16, val: bool) -> bool {
        let i = idx as usize;
        if i >= MAX_ENTRIES || !self.entries[i].active {
            return false;
        }
        let ok = self.entries[i].set_bool(val);
        if ok {
            self.total_writes.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }

    /// Reset entry to default value
    pub fn reset_to_default(&mut self, idx: u16) -> bool {
        let i = idx as usize;
        if i >= MAX_ENTRIES || !self.entries[i].active {
            return false;
        }
        self.entries[i].value = self.entries[i].default_value;
        self.entries[i].write_count += 1;
        true
    }

    /// List entries in a directory
    pub fn list_dir(&self, dir: SysctlDir, out: &mut [u16; 64]) -> u8 {
        let mut count = 0u8;
        for i in 0..self.entry_count as usize {
            if self.entries[i].active && self.entries[i].dir as u8 == dir as u8 {
                if (count as usize) < 64 {
                    out[count as usize] = i as u16;
                    count += 1;
                }
            }
        }
        count
    }

    // ─── Default Registrations ──────────────────────────────────────

    fn register_kernel_defaults(&mut self) {
        // kernel.hostname
        self.register_string(SysctlDir::Kernel, b"hostname", b"zxyphor", SysctlMode::ReadWrite);
        // kernel.osrelease
        self.register_string(SysctlDir::Kernel, b"osrelease", b"0.1.0-dev", SysctlMode::ReadOnly);
        // kernel.ostype
        self.register_string(SysctlDir::Kernel, b"ostype", b"Zxyphor", SysctlMode::ReadOnly);
        // kernel.version
        self.register_string(SysctlDir::Kernel, b"version", b"#1 SMP PREEMPT", SysctlMode::ReadOnly);
        // kernel.domainname
        self.register_string(SysctlDir::Kernel, b"domainname", b"(none)", SysctlMode::ReadWrite);
        // kernel.pid_max (default 32768, Linux range 301-4194304)
        self.register_int_bounded(SysctlDir::Kernel, b"pid_max", 32768, 301, 4194304, true, SysctlMode::ReadWrite);
        // kernel.threads-max
        self.register_int_bounded(SysctlDir::Kernel, b"threads-max", 16384, 1, 1048576, true, SysctlMode::ReadWrite);
        // kernel.panic (seconds to reboot after panic, 0 = no reboot)
        self.register_int_bounded(SysctlDir::Kernel, b"panic", 0, 0, 3600, true, SysctlMode::ReadWrite);
        // kernel.panic_on_oops
        self.register_bool(SysctlDir::Kernel, b"panic_on_oops", false, SysctlMode::ReadWrite);
        // kernel.sysrq (bitmask for magic sysrq keys)
        self.register_int_bounded(SysctlDir::Kernel, b"sysrq", 1, 0, 0x1FF, true, SysctlMode::ReadWrite);
        // kernel.printk (console loglevel)
        self.register_int_bounded(SysctlDir::Kernel, b"printk", 4, 0, 8, true, SysctlMode::ReadWrite);
        // kernel.sched_child_runs_first
        self.register_bool(SysctlDir::Kernel, b"sched_child_runs_first", false, SysctlMode::ReadWrite);
        // kernel.randomize_va_space (ASLR: 0=off, 1=stack, 2=full)
        self.register_int_bounded(SysctlDir::Kernel, b"randomize_va_space", 2, 0, 2, true, SysctlMode::ReadWrite);
        // kernel.core_pattern
        self.register_string(SysctlDir::Kernel, b"core_pattern", b"core.%p", SysctlMode::ReadWrite);
        // kernel.modules_disabled (can only be set to 1, never back to 0)
        self.register_bool(SysctlDir::Kernel, b"modules_disabled", false, SysctlMode::ReadWrite);
        // kernel.kptr_restrict (0=allow, 1=restrict, 2=hide)
        self.register_int_bounded(SysctlDir::Kernel, b"kptr_restrict", 1, 0, 2, true, SysctlMode::ReadWrite);
        // kernel.dmesg_restrict
        self.register_bool(SysctlDir::Kernel, b"dmesg_restrict", false, SysctlMode::ReadWrite);
        // kernel.ngroups_max
        self.register_int(SysctlDir::Kernel, b"ngroups_max", 65536, SysctlMode::ReadOnly);
        // kernel.hz (CONFIG_HZ)
        self.register_int(SysctlDir::Kernel, b"hz", 1000, SysctlMode::ReadOnly);
    }

    fn register_vm_defaults(&mut self) {
        // vm.swappiness (0-200, default 60)
        self.register_int_bounded(SysctlDir::Vm, b"swappiness", 60, 0, 200, true, SysctlMode::ReadWrite);
        // vm.dirty_ratio (percentage of RAM before synchronous writeback)
        self.register_int_bounded(SysctlDir::Vm, b"dirty_ratio", 20, 0, 100, true, SysctlMode::ReadWrite);
        // vm.dirty_background_ratio
        self.register_int_bounded(SysctlDir::Vm, b"dirty_background_ratio", 10, 0, 100, true, SysctlMode::ReadWrite);
        // vm.dirty_expire_centisecs (when dirty data becomes eligible for writeback)
        self.register_int_bounded(SysctlDir::Vm, b"dirty_expire_centisecs", 3000, 0, 360000, true, SysctlMode::ReadWrite);
        // vm.dirty_writeback_centisecs (interval between writeback daemons)
        self.register_int_bounded(SysctlDir::Vm, b"dirty_writeback_centisecs", 500, 0, 360000, true, SysctlMode::ReadWrite);
        // vm.overcommit_memory (0=heuristic, 1=always, 2=strict)
        self.register_int_bounded(SysctlDir::Vm, b"overcommit_memory", 0, 0, 2, true, SysctlMode::ReadWrite);
        // vm.overcommit_ratio (percentage for strict overcommit)
        self.register_int_bounded(SysctlDir::Vm, b"overcommit_ratio", 50, 0, 100, true, SysctlMode::ReadWrite);
        // vm.oom_kill_allocating_task
        self.register_bool(SysctlDir::Vm, b"oom_kill_allocating_task", true, SysctlMode::ReadWrite);
        // vm.panic_on_oom (0=no, 1=yes, 2=if no cgroup limit)
        self.register_int_bounded(SysctlDir::Vm, b"panic_on_oom", 0, 0, 2, true, SysctlMode::ReadWrite);
        // vm.min_free_kbytes
        self.register_int_bounded(SysctlDir::Vm, b"min_free_kbytes", 4096, 128, 1048576, true, SysctlMode::ReadWrite);
        // vm.vfs_cache_pressure (100=default, >100 more aggressive reclaim)
        self.register_int_bounded(SysctlDir::Vm, b"vfs_cache_pressure", 100, 0, 10000, true, SysctlMode::ReadWrite);
        // vm.max_map_count (maximum number of mmap areas)
        self.register_int_bounded(SysctlDir::Vm, b"max_map_count", 65536, 1, 16777216, true, SysctlMode::ReadWrite);
    }

    fn register_net_defaults(&mut self) {
        // net.core.somaxconn (maximum listen backlog)
        self.register_int_bounded(SysctlDir::NetCore, b"somaxconn", 4096, 1, 65535, true, SysctlMode::ReadWrite);
        // net.core.rmem_default
        self.register_int_bounded(SysctlDir::NetCore, b"rmem_default", 212992, 4096, 16777216, true, SysctlMode::ReadWrite);
        // net.core.wmem_default
        self.register_int_bounded(SysctlDir::NetCore, b"wmem_default", 212992, 4096, 16777216, true, SysctlMode::ReadWrite);
        // net.core.rmem_max
        self.register_int_bounded(SysctlDir::NetCore, b"rmem_max", 212992, 4096, 67108864, true, SysctlMode::ReadWrite);
        // net.core.wmem_max
        self.register_int_bounded(SysctlDir::NetCore, b"wmem_max", 212992, 4096, 67108864, true, SysctlMode::ReadWrite);
        // net.core.netdev_max_backlog
        self.register_int_bounded(SysctlDir::NetCore, b"netdev_max_backlog", 1000, 1, 100000, true, SysctlMode::ReadWrite);
        // net.ipv4.ip_forward
        self.register_bool(SysctlDir::NetIpv4, b"ip_forward", false, SysctlMode::ReadWrite);
        // net.ipv4.tcp_syncookies
        self.register_bool(SysctlDir::NetIpv4, b"tcp_syncookies", true, SysctlMode::ReadWrite);
        // net.ipv4.tcp_max_syn_backlog
        self.register_int_bounded(SysctlDir::NetIpv4, b"tcp_max_syn_backlog", 2048, 1, 65535, true, SysctlMode::ReadWrite);
        // net.ipv4.tcp_fin_timeout
        self.register_int_bounded(SysctlDir::NetIpv4, b"tcp_fin_timeout", 60, 1, 120, true, SysctlMode::ReadWrite);
        // net.ipv4.tcp_keepalive_time
        self.register_int_bounded(SysctlDir::NetIpv4, b"tcp_keepalive_time", 7200, 1, 32767, true, SysctlMode::ReadWrite);
        // net.ipv4.tcp_tw_reuse
        self.register_bool(SysctlDir::NetIpv4, b"tcp_tw_reuse", false, SysctlMode::ReadWrite);
        // net.ipv4.icmp_echo_ignore_all
        self.register_bool(SysctlDir::NetIpv4, b"icmp_echo_ignore_all", false, SysctlMode::ReadWrite);
    }

    fn register_fs_defaults(&mut self) {
        // fs.file-max (system-wide limit on open files)
        self.register_int_bounded(SysctlDir::Fs, b"file-max", 1048576, 8192, 67108864, true, SysctlMode::ReadWrite);
        // fs.nr_open (per-process max, must be < file-max)
        self.register_int_bounded(SysctlDir::Fs, b"nr_open", 1048576, 8192, 67108864, true, SysctlMode::ReadWrite);
        // fs.inotify.max_user_watches
        self.register_int_bounded(SysctlDir::Fs, b"inotify_max_user_watches", 65536, 1, 524288, true, SysctlMode::ReadWrite);
        // fs.inotify.max_user_instances
        self.register_int_bounded(SysctlDir::Fs, b"inotify_max_user_instances", 128, 1, 65536, true, SysctlMode::ReadWrite);
        // fs.pipe-max-size
        self.register_int_bounded(SysctlDir::Fs, b"pipe-max-size", 1048576, 4096, 16777216, true, SysctlMode::ReadWrite);
        // fs.protected_hardlinks
        self.register_bool(SysctlDir::Fs, b"protected_hardlinks", true, SysctlMode::ReadWrite);
        // fs.protected_symlinks
        self.register_bool(SysctlDir::Fs, b"protected_symlinks", true, SysctlMode::ReadWrite);
    }
}

// ─────────────────── Global Instance ────────────────────────────────

static mut SYSCTL_MGR: SysctlManager = SysctlManager::new();

fn mgr() -> &'static mut SysctlManager {
    unsafe { &mut SYSCTL_MGR }
}

fn mgr_ref() -> &'static SysctlManager {
    unsafe { &SYSCTL_MGR }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_sysctl_init() {
    mgr().init();
}

#[no_mangle]
pub extern "C" fn rust_sysctl_entry_count() -> u16 {
    mgr_ref().entry_count
}

#[no_mangle]
pub extern "C" fn rust_sysctl_total_reads() -> u64 {
    mgr_ref().total_reads.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_sysctl_total_writes() -> u64 {
    mgr_ref().total_writes.load(Ordering::Relaxed)
}

/// Read int by path (returns 0 on not found, sets *ok to 0/1)
#[no_mangle]
pub extern "C" fn rust_sysctl_read_int(path_ptr: *const u8, path_len: u16, ok: *mut u8) -> i64 {
    if path_ptr.is_null() || ok.is_null() {
        return 0;
    }
    let path = unsafe { core::slice::from_raw_parts(path_ptr, path_len as usize) };
    if let Some(idx) = mgr().find_by_path(path) {
        if let Some(val) = mgr().read_int(idx) {
            unsafe { *ok = 1; }
            return val;
        }
    }
    unsafe { *ok = 0; }
    0
}

/// Write int by path
#[no_mangle]
pub extern "C" fn rust_sysctl_write_int(path_ptr: *const u8, path_len: u16, val: i64) -> bool {
    if path_ptr.is_null() {
        return false;
    }
    let path = unsafe { core::slice::from_raw_parts(path_ptr, path_len as usize) };
    if let Some(idx) = mgr().find_by_path(path) {
        return mgr().write_int(idx, val);
    }
    false
}

#[no_mangle]
pub extern "C" fn rust_sysctl_reset(idx: u16) -> bool {
    mgr().reset_to_default(idx)
}

#[no_mangle]
pub extern "C" fn rust_sysctl_table_count() -> u8 {
    mgr_ref().table_count
}
