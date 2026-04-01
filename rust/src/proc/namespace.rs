// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Rust Namespace Subsystem
//
// Implements Linux-style namespaces for process isolation:
// - PID namespace (process ID isolation)
// - Mount namespace (filesystem mount points)
// - Network namespace (network stack isolation)
// - UTS namespace (hostname/domainname)
// - IPC namespace (System V IPC isolation)
// - User namespace (UID/GID mapping)
// - Cgroup namespace
// - Time namespace

#![allow(dead_code)]

// ─────────────────── Constants ──────────────────────────────────────
pub const MAX_NAMESPACES: usize = 1024;
pub const MAX_PID_NS: usize = 256;
pub const MAX_NS_DEPTH: usize = 32;
pub const MAX_UID_MAPPINGS: usize = 5;
pub const MAX_MOUNT_POINTS: usize = 256;
pub const MAX_HOSTNAME_LEN: usize = 64;
pub const MAX_DOMAINNAME_LEN: usize = 64;

// ─────────────────── Namespace Types ────────────────────────────────
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsType {
    Pid = 0x20000000,
    Mount = 0x00020000,
    Network = 0x40000000,
    Uts = 0x04000000,
    Ipc = 0x08000000,
    User = 0x10000000,
    Cgroup = 0x02000000,
    Time = 0x00000080,
}

impl NsType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Pid => "pid",
            Self::Mount => "mnt",
            Self::Network => "net",
            Self::Uts => "uts",
            Self::Ipc => "ipc",
            Self::User => "user",
            Self::Cgroup => "cgroup",
            Self::Time => "time",
        }
    }

    pub fn all() -> &'static [NsType] {
        &[
            NsType::Pid, NsType::Mount, NsType::Network, NsType::Uts,
            NsType::Ipc, NsType::User, NsType::Cgroup, NsType::Time,
        ]
    }
}

// ─────────────────── Namespace Base ─────────────────────────────────
#[derive(Debug, Clone, Copy)]
pub struct NsCommon {
    pub id: u32,
    pub ns_type: NsType,
    pub parent_id: u32,
    pub depth: u8,
    pub ref_count: u32,
    pub owner_uid: u32,
    pub created_pid: u32,
}

impl NsCommon {
    pub fn new(id: u32, ns_type: NsType, parent_id: u32, depth: u8) -> Self {
        Self {
            id,
            ns_type,
            parent_id,
            depth,
            ref_count: 1,
            owner_uid: 0,
            created_pid: 0,
        }
    }

    pub fn acquire(&mut self) {
        self.ref_count += 1;
    }

    pub fn release(&mut self) -> bool {
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
        self.ref_count == 0
    }
}

// ─────────────────── PID Namespace ──────────────────────────────────
pub struct PidNamespace {
    pub common: NsCommon,
    /// PID allocation bitmap
    pub pid_bitmap: [u64; 1024],  // Supports up to 65536 PIDs
    /// Maximum PID value in this namespace
    pub pid_max: u32,
    /// Next PID to try allocating
    pub last_pid: u32,
    /// Number of active processes
    pub nr_processes: u32,
    /// Child reaper PID (init process for this namespace)
    pub child_reaper_pid: u32,
    /// Nested depth level
    pub level: u8,
}

impl PidNamespace {
    pub fn new(common: NsCommon, pid_max: u32) -> Self {
        Self {
            common,
            pid_bitmap: [0; 1024],
            pid_max: pid_max.min(65536),
            last_pid: 0,
            nr_processes: 0,
            child_reaper_pid: 1,
            level: common.depth,
        }
    }

    /// Allocate a new PID in this namespace
    pub fn alloc_pid(&mut self) -> Option<u32> {
        let max = self.pid_max as usize;
        let start = (self.last_pid as usize + 1) % max;

        for i in 0..max {
            let pid = ((start + i) % max) as u32;
            if pid == 0 { continue; } // PID 0 reserved

            let word = pid as usize / 64;
            let bit = pid as usize % 64;
            if word < 1024 && (self.pid_bitmap[word] & (1u64 << bit)) == 0 {
                self.pid_bitmap[word] |= 1u64 << bit;
                self.last_pid = pid;
                self.nr_processes += 1;
                return Some(pid);
            }
        }
        None
    }

    /// Free a PID
    pub fn free_pid(&mut self, pid: u32) {
        let word = pid as usize / 64;
        let bit = pid as usize % 64;
        if word < 1024 {
            self.pid_bitmap[word] &= !(1u64 << bit);
            if self.nr_processes > 0 {
                self.nr_processes -= 1;
            }
        }
    }

    /// Check if a PID is allocated
    pub fn pid_exists(&self, pid: u32) -> bool {
        let word = pid as usize / 64;
        let bit = pid as usize % 64;
        if word >= 1024 { return false; }
        (self.pid_bitmap[word] & (1u64 << bit)) != 0
    }
}

// ─────────────────── UTS Namespace ──────────────────────────────────
pub struct UtsNamespace {
    pub common: NsCommon,
    pub hostname: [u8; MAX_HOSTNAME_LEN],
    pub hostname_len: usize,
    pub domainname: [u8; MAX_DOMAINNAME_LEN],
    pub domainname_len: usize,
    pub sysname: [u8; 32],
    pub sysname_len: usize,
    pub release: [u8; 32],
    pub release_len: usize,
    pub version: [u8; 64],
    pub version_len: usize,
    pub machine: [u8; 32],
    pub machine_len: usize,
}

impl UtsNamespace {
    pub fn new(common: NsCommon) -> Self {
        let mut ns = Self {
            common,
            hostname: [0; MAX_HOSTNAME_LEN],
            hostname_len: 0,
            domainname: [0; MAX_DOMAINNAME_LEN],
            domainname_len: 0,
            sysname: [0; 32],
            sysname_len: 0,
            release: [0; 32],
            release_len: 0,
            version: [0; 64],
            version_len: 0,
            machine: [0; 32],
            machine_len: 0,
        };

        // Set defaults
        ns.set_sysname(b"Zxyphor");
        ns.set_release(b"1.0.0");
        ns.set_version(b"#1 SMP");
        ns.set_machine(b"x86_64");
        ns.set_hostname(b"zxyphor");
        ns
    }

    pub fn set_hostname(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_HOSTNAME_LEN);
        self.hostname[..len].copy_from_slice(&name[..len]);
        self.hostname_len = len;
    }

    pub fn get_hostname(&self) -> &[u8] {
        &self.hostname[..self.hostname_len]
    }

    pub fn set_domainname(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_DOMAINNAME_LEN);
        self.domainname[..len].copy_from_slice(&name[..len]);
        self.domainname_len = len;
    }

    pub fn get_domainname(&self) -> &[u8] {
        &self.domainname[..self.domainname_len]
    }

    fn set_sysname(&mut self, name: &[u8]) {
        let len = name.len().min(32);
        self.sysname[..len].copy_from_slice(&name[..len]);
        self.sysname_len = len;
    }

    fn set_release(&mut self, rel: &[u8]) {
        let len = rel.len().min(32);
        self.release[..len].copy_from_slice(&rel[..len]);
        self.release_len = len;
    }

    fn set_version(&mut self, ver: &[u8]) {
        let len = ver.len().min(64);
        self.version[..len].copy_from_slice(&ver[..len]);
        self.version_len = len;
    }

    fn set_machine(&mut self, machine: &[u8]) {
        let len = machine.len().min(32);
        self.machine[..len].copy_from_slice(&machine[..len]);
        self.machine_len = len;
    }
}

// ─────────────────── User Namespace ─────────────────────────────────
#[derive(Debug, Clone, Copy)]
pub struct IdMapping {
    /// ID in the child namespace
    pub inner_id: u32,
    /// ID in the parent namespace
    pub outer_id: u32,
    /// Number of IDs in the range
    pub count: u32,
}

pub struct UserNamespace {
    pub common: NsCommon,
    pub uid_map: [Option<IdMapping>; MAX_UID_MAPPINGS],
    pub gid_map: [Option<IdMapping>; MAX_UID_MAPPINGS],
    pub uid_map_count: u8,
    pub gid_map_count: u8,
    /// Owner UID in parent namespace
    pub owner: u32,
    /// Owner GID in parent namespace
    pub group: u32,
    /// Capabilities in this namespace
    pub flags: u32,
}

impl UserNamespace {
    pub fn new(common: NsCommon, owner: u32, group: u32) -> Self {
        const NONE_MAP: Option<IdMapping> = None;
        Self {
            common,
            uid_map: [NONE_MAP; MAX_UID_MAPPINGS],
            gid_map: [NONE_MAP; MAX_UID_MAPPINGS],
            uid_map_count: 0,
            gid_map_count: 0,
            owner,
            group,
            flags: 0,
        }
    }

    /// Add a UID mapping
    pub fn add_uid_mapping(&mut self, inner: u32, outer: u32, count: u32) -> bool {
        if self.uid_map_count as usize >= MAX_UID_MAPPINGS { return false; }
        let idx = self.uid_map_count as usize;
        self.uid_map[idx] = Some(IdMapping { inner_id: inner, outer_id: outer, count });
        self.uid_map_count += 1;
        true
    }

    /// Add a GID mapping
    pub fn add_gid_mapping(&mut self, inner: u32, outer: u32, count: u32) -> bool {
        if self.gid_map_count as usize >= MAX_UID_MAPPINGS { return false; }
        let idx = self.gid_map_count as usize;
        self.gid_map[idx] = Some(IdMapping { inner_id: inner, outer_id: outer, count });
        self.gid_map_count += 1;
        true
    }

    /// Translate a UID from inner to outer namespace
    pub fn uid_to_outer(&self, inner_uid: u32) -> Option<u32> {
        for mapping in &self.uid_map[..self.uid_map_count as usize] {
            if let Some(m) = mapping {
                if inner_uid >= m.inner_id && inner_uid < m.inner_id + m.count {
                    return Some(m.outer_id + (inner_uid - m.inner_id));
                }
            }
        }
        None // Overflow UID
    }

    /// Translate a UID from outer to inner namespace
    pub fn uid_to_inner(&self, outer_uid: u32) -> Option<u32> {
        for mapping in &self.uid_map[..self.uid_map_count as usize] {
            if let Some(m) = mapping {
                if outer_uid >= m.outer_id && outer_uid < m.outer_id + m.count {
                    return Some(m.inner_id + (outer_uid - m.outer_id));
                }
            }
        }
        None
    }

    /// Translate a GID from inner to outer namespace
    pub fn gid_to_outer(&self, inner_gid: u32) -> Option<u32> {
        for mapping in &self.gid_map[..self.gid_map_count as usize] {
            if let Some(m) = mapping {
                if inner_gid >= m.inner_id && inner_gid < m.inner_id + m.count {
                    return Some(m.outer_id + (inner_gid - m.inner_id));
                }
            }
        }
        None
    }

    /// Translate a GID from outer to inner namespace
    pub fn gid_to_inner(&self, outer_gid: u32) -> Option<u32> {
        for mapping in &self.gid_map[..self.gid_map_count as usize] {
            if let Some(m) = mapping {
                if outer_gid >= m.outer_id && outer_gid < m.outer_id + m.count {
                    return Some(m.inner_id + (outer_gid - m.outer_id));
                }
            }
        }
        None
    }
}

// ─────────────────── Mount Namespace ────────────────────────────────
#[derive(Debug, Clone, Copy)]
pub struct MountPoint {
    pub id: u32,
    pub parent_id: u32,
    /// Device major:minor
    pub dev_major: u32,
    pub dev_minor: u32,
    /// Mount flags
    pub flags: MountFlags,
    /// Path (simplified)
    pub path: [u8; 128],
    pub path_len: usize,
    /// Filesystem type name
    pub fs_type: [u8; 16],
    pub fs_type_len: usize,
    /// Source device path
    pub source: [u8; 64],
    pub source_len: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct MountFlags {
    pub readonly: bool,
    pub nosuid: bool,
    pub nodev: bool,
    pub noexec: bool,
    pub synchronous: bool,
    pub noatime: bool,
    pub nodiratime: bool,
    pub relatime: bool,
    pub bind: bool,
    pub shared: bool,
    pub slave: bool,
    pub private_: bool,
    pub unbindable: bool,
}

impl Default for MountFlags {
    fn default() -> Self {
        Self {
            readonly: false,
            nosuid: false,
            nodev: false,
            noexec: false,
            synchronous: false,
            noatime: false,
            nodiratime: false,
            relatime: true,
            bind: false,
            shared: false,
            slave: false,
            private_: false,
            unbindable: false,
        }
    }
}

impl MountPoint {
    pub fn new(id: u32, parent_id: u32) -> Self {
        Self {
            id,
            parent_id,
            dev_major: 0,
            dev_minor: 0,
            flags: MountFlags::default(),
            path: [0; 128],
            path_len: 0,
            fs_type: [0; 16],
            fs_type_len: 0,
            source: [0; 64],
            source_len: 0,
        }
    }

    pub fn set_path(&mut self, path: &[u8]) {
        let len = path.len().min(128);
        self.path[..len].copy_from_slice(&path[..len]);
        self.path_len = len;
    }

    pub fn set_fs_type(&mut self, fstype: &[u8]) {
        let len = fstype.len().min(16);
        self.fs_type[..len].copy_from_slice(&fstype[..len]);
        self.fs_type_len = len;
    }

    pub fn set_source(&mut self, src: &[u8]) {
        let len = src.len().min(64);
        self.source[..len].copy_from_slice(&src[..len]);
        self.source_len = len;
    }
}

pub struct MountNamespace {
    pub common: NsCommon,
    pub mounts: [Option<MountPoint>; MAX_MOUNT_POINTS],
    pub mount_count: u32,
    pub next_mount_id: u32,
}

impl MountNamespace {
    pub fn new(common: NsCommon) -> Self {
        const NONE_MOUNT: Option<MountPoint> = None;
        let mut ns = Self {
            common,
            mounts: [NONE_MOUNT; MAX_MOUNT_POINTS],
            mount_count: 0,
            next_mount_id: 1,
        };

        // Create root mount
        let mut root = MountPoint::new(0, 0);
        root.set_path(b"/");
        root.set_fs_type(b"rootfs");
        ns.mounts[0] = Some(root);
        ns.mount_count = 1;

        ns
    }

    pub fn mount(
        &mut self,
        source: &[u8],
        path: &[u8],
        fs_type: &[u8],
        flags: MountFlags,
    ) -> Option<u32> {
        if self.mount_count as usize >= MAX_MOUNT_POINTS { return None; }

        let id = self.next_mount_id;
        self.next_mount_id += 1;

        let mut mp = MountPoint::new(id, 0); // TODO: find parent
        mp.set_path(path);
        mp.set_fs_type(fs_type);
        mp.set_source(source);
        mp.flags = flags;

        for slot in self.mounts.iter_mut() {
            if slot.is_none() {
                *slot = Some(mp);
                self.mount_count += 1;
                return Some(id);
            }
        }
        None
    }

    pub fn umount(&mut self, mount_id: u32) -> bool {
        for slot in self.mounts.iter_mut() {
            if let Some(mp) = slot {
                if mp.id == mount_id && mount_id != 0 { // Can't unmount root
                    *slot = None;
                    if self.mount_count > 0 {
                        self.mount_count -= 1;
                    }
                    return true;
                }
            }
        }
        false
    }

    pub fn find_mount_by_path(&self, path: &[u8]) -> Option<&MountPoint> {
        for slot in &self.mounts {
            if let Some(mp) = slot {
                if mp.path_len == path.len() && &mp.path[..mp.path_len] == path {
                    return Some(mp);
                }
            }
        }
        None
    }
}

// ─────────────────── Network Namespace ──────────────────────────────
pub struct NetNamespace {
    pub common: NsCommon,
    /// Loopback device index
    pub loopback_dev: u32,
    /// Network interfaces in this namespace
    pub interfaces: [Option<NetIfInfo>; 32],
    pub if_count: u32,
    /// Routing table entries
    pub routes: [Option<RouteEntry>; 64],
    pub route_count: u32,
    /// IPTables rule count (simplified)
    pub iptables_rules: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct NetIfInfo {
    pub index: u32,
    pub name: [u8; 16],
    pub name_len: usize,
    pub mac: [u8; 6],
    pub ipv4_addr: u32,
    pub ipv4_mask: u32,
    pub flags: u32,
    pub mtu: u32,
}

impl NetIfInfo {
    pub fn loopback() -> Self {
        let mut iface = Self {
            index: 1,
            name: [0; 16],
            name_len: 2,
            mac: [0; 6],
            ipv4_addr: 0x7F000001, // 127.0.0.1
            ipv4_mask: 0xFF000000,
            flags: 0x0001 | 0x0008, // UP | LOOPBACK
            mtu: 65536,
        };
        iface.name[0] = b'l';
        iface.name[1] = b'o';
        iface
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RouteEntry {
    pub dest: u32,
    pub mask: u32,
    pub gateway: u32,
    pub iface_index: u32,
    pub metric: u32,
    pub flags: u32,
}

impl NetNamespace {
    pub fn new(common: NsCommon) -> Self {
        const NONE_IF: Option<NetIfInfo> = None;
        const NONE_RT: Option<RouteEntry> = None;

        let mut ns = Self {
            common,
            loopback_dev: 1,
            interfaces: [NONE_IF; 32],
            if_count: 0,
            routes: [NONE_RT; 64],
            route_count: 0,
            iptables_rules: 0,
        };

        // Create loopback device
        ns.interfaces[0] = Some(NetIfInfo::loopback());
        ns.if_count = 1;

        // Add loopback route
        ns.routes[0] = Some(RouteEntry {
            dest: 0x7F000000,
            mask: 0xFF000000,
            gateway: 0,
            iface_index: 1,
            metric: 0,
            flags: 1,
        });
        ns.route_count = 1;

        ns
    }

    pub fn add_interface(&mut self, iface: NetIfInfo) -> bool {
        if self.if_count as usize >= 32 { return false; }
        for slot in self.interfaces.iter_mut() {
            if slot.is_none() {
                *slot = Some(iface);
                self.if_count += 1;
                return true;
            }
        }
        false
    }

    pub fn add_route(&mut self, route: RouteEntry) -> bool {
        if self.route_count as usize >= 64 { return false; }
        for slot in self.routes.iter_mut() {
            if slot.is_none() {
                *slot = Some(route);
                self.route_count += 1;
                return true;
            }
        }
        false
    }
}

// ─────────────────── IPC Namespace ──────────────────────────────────
pub struct IpcNamespace {
    pub common: NsCommon,
    /// Shared memory limits
    pub shmmax: u64,
    pub shmall: u64,
    pub shmmni: u32,
    /// Semaphore limits
    pub semmsl: u32,
    pub semmns: u32,
    pub semopm: u32,
    pub semmni: u32,
    /// Message queue limits
    pub msgmax: u32,
    pub msgmnb: u32,
    pub msgmni: u32,
    /// Current allocations
    pub shm_count: u32,
    pub sem_count: u32,
    pub msg_count: u32,
}

impl IpcNamespace {
    pub fn new(common: NsCommon) -> Self {
        Self {
            common,
            shmmax: 33554432,   // 32MB
            shmall: 2097152,    // 8GB in pages
            shmmni: 4096,
            semmsl: 32000,
            semmns: 1024000000,
            semopm: 500,
            semmni: 32000,
            msgmax: 8192,
            msgmnb: 16384,
            msgmni: 32000,
            shm_count: 0,
            sem_count: 0,
            msg_count: 0,
        }
    }
}

// ─────────────────── Cgroup Namespace ───────────────────────────────
pub struct CgroupNamespace {
    pub common: NsCommon,
    /// Root cgroup path for this namespace
    pub root_path: [u8; 128],
    pub root_path_len: usize,
}

impl CgroupNamespace {
    pub fn new(common: NsCommon) -> Self {
        let mut ns = Self {
            common,
            root_path: [0; 128],
            root_path_len: 0,
        };
        ns.set_root_path(b"/");
        ns
    }

    pub fn set_root_path(&mut self, path: &[u8]) {
        let len = path.len().min(128);
        self.root_path[..len].copy_from_slice(&path[..len]);
        self.root_path_len = len;
    }
}

// ─────────────────── Time Namespace ─────────────────────────────────
pub struct TimeNamespace {
    pub common: NsCommon,
    /// Monotonic clock offset (nanoseconds)
    pub monotonic_offset_ns: i64,
    /// Boottime offset (nanoseconds)
    pub boottime_offset_ns: i64,
}

impl TimeNamespace {
    pub fn new(common: NsCommon) -> Self {
        Self {
            common,
            monotonic_offset_ns: 0,
            boottime_offset_ns: 0,
        }
    }

    pub fn set_monotonic_offset(&mut self, offset_ns: i64) {
        self.monotonic_offset_ns = offset_ns;
    }

    pub fn set_boottime_offset(&mut self, offset_ns: i64) {
        self.boottime_offset_ns = offset_ns;
    }

    pub fn translate_monotonic(&self, host_ns: u64) -> u64 {
        (host_ns as i64 + self.monotonic_offset_ns) as u64
    }

    pub fn translate_boottime(&self, host_ns: u64) -> u64 {
        (host_ns as i64 + self.boottime_offset_ns) as u64
    }
}

// ─────────────────── Process Namespace Set ──────────────────────────
/// Complete set of namespaces for a process
#[derive(Debug, Clone, Copy)]
pub struct NsSet {
    pub pid_ns_id: u32,
    pub mount_ns_id: u32,
    pub net_ns_id: u32,
    pub uts_ns_id: u32,
    pub ipc_ns_id: u32,
    pub user_ns_id: u32,
    pub cgroup_ns_id: u32,
    pub time_ns_id: u32,
}

impl Default for NsSet {
    fn default() -> Self {
        Self {
            pid_ns_id: 0,
            mount_ns_id: 0,
            net_ns_id: 0,
            uts_ns_id: 0,
            ipc_ns_id: 0,
            user_ns_id: 0,
            cgroup_ns_id: 0,
            time_ns_id: 0,
        }
    }
}

// ─────────────────── Namespace Manager ──────────────────────────────
pub struct NamespaceManager {
    pid_namespaces: [Option<PidNamespace>; 64],
    uts_namespaces: [Option<UtsNamespace>; 64],
    user_namespaces: [Option<UserNamespace>; 64],
    mount_namespaces: [Option<MountNamespace>; 32],
    net_namespaces: [Option<NetNamespace>; 32],
    ipc_namespaces: [Option<IpcNamespace>; 32],
    cgroup_namespaces: [Option<CgroupNamespace>; 32],
    time_namespaces: [Option<TimeNamespace>; 32],

    /// Counters
    pid_ns_count: usize,
    uts_ns_count: usize,
    user_ns_count: usize,
    mount_ns_count: usize,
    net_ns_count: usize,
    ipc_ns_count: usize,
    cgroup_ns_count: usize,
    time_ns_count: usize,

    next_ns_id: u32,
    /// Initial namespace set (the "root" namespaces)
    init_ns_set: NsSet,
}

impl NamespaceManager {
    pub fn new() -> Self {
        const NONE_PID: Option<PidNamespace> = None;
        const NONE_UTS: Option<UtsNamespace> = None;
        const NONE_USER: Option<UserNamespace> = None;
        const NONE_MNT: Option<MountNamespace> = None;
        const NONE_NET: Option<NetNamespace> = None;
        const NONE_IPC: Option<IpcNamespace> = None;
        const NONE_CG: Option<CgroupNamespace> = None;
        const NONE_TIME: Option<TimeNamespace> = None;

        Self {
            pid_namespaces: [NONE_PID; 64],
            uts_namespaces: [NONE_UTS; 64],
            user_namespaces: [NONE_USER; 64],
            mount_namespaces: [NONE_MNT; 32],
            net_namespaces: [NONE_NET; 32],
            ipc_namespaces: [NONE_IPC; 32],
            cgroup_namespaces: [NONE_CG; 32],
            time_namespaces: [NONE_TIME; 32],
            pid_ns_count: 0,
            uts_ns_count: 0,
            user_ns_count: 0,
            mount_ns_count: 0,
            net_ns_count: 0,
            ipc_ns_count: 0,
            cgroup_ns_count: 0,
            time_ns_count: 0,
            next_ns_id: 1,
            init_ns_set: NsSet::default(),
        }
    }

    /// Initialize the root namespace set
    pub fn init(&mut self) {
        // Create initial PID namespace
        let pid_id = self.alloc_id();
        let pid_common = NsCommon::new(pid_id, NsType::Pid, 0, 0);
        let pid_ns = PidNamespace::new(pid_common, 32768);
        self.pid_namespaces[0] = Some(pid_ns);
        self.pid_ns_count = 1;
        self.init_ns_set.pid_ns_id = pid_id;

        // Create initial UTS namespace
        let uts_id = self.alloc_id();
        let uts_common = NsCommon::new(uts_id, NsType::Uts, 0, 0);
        self.uts_namespaces[0] = Some(UtsNamespace::new(uts_common));
        self.uts_ns_count = 1;
        self.init_ns_set.uts_ns_id = uts_id;

        // Create initial user namespace
        let user_id = self.alloc_id();
        let user_common = NsCommon::new(user_id, NsType::User, 0, 0);
        let mut user_ns = UserNamespace::new(user_common, 0, 0);
        // Root user: maps 0..65536 → 0..65536
        user_ns.add_uid_mapping(0, 0, 65536);
        user_ns.add_gid_mapping(0, 0, 65536);
        self.user_namespaces[0] = Some(user_ns);
        self.user_ns_count = 1;
        self.init_ns_set.user_ns_id = user_id;

        // Create initial mount namespace
        let mnt_id = self.alloc_id();
        let mnt_common = NsCommon::new(mnt_id, NsType::Mount, 0, 0);
        self.mount_namespaces[0] = Some(MountNamespace::new(mnt_common));
        self.mount_ns_count = 1;
        self.init_ns_set.mount_ns_id = mnt_id;

        // Create initial network namespace
        let net_id = self.alloc_id();
        let net_common = NsCommon::new(net_id, NsType::Network, 0, 0);
        self.net_namespaces[0] = Some(NetNamespace::new(net_common));
        self.net_ns_count = 1;
        self.init_ns_set.net_ns_id = net_id;

        // Create initial IPC namespace
        let ipc_id = self.alloc_id();
        let ipc_common = NsCommon::new(ipc_id, NsType::Ipc, 0, 0);
        self.ipc_namespaces[0] = Some(IpcNamespace::new(ipc_common));
        self.ipc_ns_count = 1;
        self.init_ns_set.ipc_ns_id = ipc_id;

        // Create initial cgroup namespace
        let cg_id = self.alloc_id();
        let cg_common = NsCommon::new(cg_id, NsType::Cgroup, 0, 0);
        self.cgroup_namespaces[0] = Some(CgroupNamespace::new(cg_common));
        self.cgroup_ns_count = 1;
        self.init_ns_set.cgroup_ns_id = cg_id;

        // Create initial time namespace
        let time_id = self.alloc_id();
        let time_common = NsCommon::new(time_id, NsType::Time, 0, 0);
        self.time_namespaces[0] = Some(TimeNamespace::new(time_common));
        self.time_ns_count = 1;
        self.init_ns_set.time_ns_id = time_id;
    }

    fn alloc_id(&mut self) -> u32 {
        let id = self.next_ns_id;
        self.next_ns_id += 1;
        id
    }

    /// Get the initial namespace set
    pub fn init_ns_set(&self) -> NsSet {
        self.init_ns_set
    }

    /// Create a new PID namespace
    pub fn create_pid_ns(&mut self, parent_id: u32) -> Option<u32> {
        if self.pid_ns_count >= 64 { return None; }
        let id = self.alloc_id();
        let depth = self.find_pid_ns(parent_id).map_or(0, |ns| ns.level + 1);
        if depth as usize >= MAX_NS_DEPTH { return None; }
        let common = NsCommon::new(id, NsType::Pid, parent_id, depth);
        let ns = PidNamespace::new(common, 32768);
        for slot in self.pid_namespaces.iter_mut() {
            if slot.is_none() {
                *slot = Some(ns);
                self.pid_ns_count += 1;
                return Some(id);
            }
        }
        None
    }

    /// Create a new UTS namespace (cloned from parent)
    pub fn create_uts_ns(&mut self, parent_id: u32) -> Option<u32> {
        if self.uts_ns_count >= 64 { return None; }
        let id = self.alloc_id();
        let common = NsCommon::new(id, NsType::Uts, parent_id, 0);
        let mut ns = UtsNamespace::new(common);

        // Copy hostname/domainname from parent
        if let Some(parent) = self.find_uts_ns(parent_id) {
            ns.hostname = parent.hostname;
            ns.hostname_len = parent.hostname_len;
            ns.domainname = parent.domainname;
            ns.domainname_len = parent.domainname_len;
        }

        for slot in self.uts_namespaces.iter_mut() {
            if slot.is_none() {
                *slot = Some(ns);
                self.uts_ns_count += 1;
                return Some(id);
            }
        }
        None
    }

    fn find_pid_ns(&self, id: u32) -> Option<&PidNamespace> {
        self.pid_namespaces.iter().flatten().find(|ns| ns.common.id == id)
    }

    fn find_uts_ns(&self, id: u32) -> Option<&UtsNamespace> {
        self.uts_namespaces.iter().flatten().find(|ns| ns.common.id == id)
    }

    /// Total number of namespaces
    pub fn total_count(&self) -> usize {
        self.pid_ns_count + self.uts_ns_count + self.user_ns_count +
        self.mount_ns_count + self.net_ns_count + self.ipc_ns_count +
        self.cgroup_ns_count + self.time_ns_count
    }
}

// ─────────────────── Global Instance ────────────────────────────────
static mut NS_MANAGER: Option<NamespaceManager> = None;

pub fn init() {
    unsafe {
        let mut mgr = NamespaceManager::new();
        mgr.init();
        NS_MANAGER = Some(mgr);
    }
}

pub fn get_manager() -> Option<&'static mut NamespaceManager> {
    unsafe { NS_MANAGER.as_mut() }
}

// ─────────────────── C FFI Exports ──────────────────────────────────
#[no_mangle]
pub extern "C" fn rust_ns_init() {
    init();
}

#[no_mangle]
pub extern "C" fn rust_ns_create_pid(parent_id: u32) -> i32 {
    get_manager().and_then(|m| m.create_pid_ns(parent_id)).map_or(-1, |id| id as i32)
}

#[no_mangle]
pub extern "C" fn rust_ns_create_uts(parent_id: u32) -> i32 {
    get_manager().and_then(|m| m.create_uts_ns(parent_id)).map_or(-1, |id| id as i32)
}

#[no_mangle]
pub extern "C" fn rust_ns_total_count() -> u32 {
    get_manager().map_or(0, |m| m.total_count() as u32)
}
