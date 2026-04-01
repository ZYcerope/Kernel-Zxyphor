// =============================================================================
// Kernel Zxyphor — Rust cgroup v2 Subsystem
// =============================================================================
// Linux cgroup v2-compatible resource management:
//   - Unified hierarchy (single tree)
//   - Controllers: cpu, memory, io, pids, cpuset, hugetlb, rdma
//   - Threaded mode for thread-level grouping
//   - Pressure stall information (PSI)
//   - Delegation (delegate management to non-root)
//   - Subtree control
//   - cgroup.events notifications
//   - Freezer (FROZEN / THAWED state)
//   - Weight-based CPU distribution
//   - Memory high/max/min/low limits
//   - IO bandwidth and IOPS limits
//   - PID limits
//   - cpuset partition support
// =============================================================================

/// Maximum cgroups in the hierarchy
const MAX_CGROUPS: usize = 256;
/// Maximum children per cgroup
const MAX_CHILDREN: usize = 32;
/// Maximum processes per cgroup
const MAX_PROCS: usize = 128;
/// Maximum IO devices with limits
const MAX_IO_DEVICES: usize = 8;

// ---------------------------------------------------------------------------
// Controller types (bitmask)
// ---------------------------------------------------------------------------

pub const CTRL_CPU: u32    = 0x0001;
pub const CTRL_MEMORY: u32 = 0x0002;
pub const CTRL_IO: u32     = 0x0004;
pub const CTRL_PIDS: u32   = 0x0008;
pub const CTRL_CPUSET: u32 = 0x0010;
pub const CTRL_HUGETLB: u32= 0x0020;
pub const CTRL_RDMA: u32   = 0x0040;
pub const CTRL_ALL: u32    = 0x007F;

// ---------------------------------------------------------------------------
// Memory controller
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct MemoryController {
    pub min: u64,       // guaranteed minimum
    pub low: u64,       // best-effort minimum
    pub high: u64,      // throttle threshold
    pub max: u64,       // hard limit (OOM kill above)
    pub swap_max: u64,  // swap limit
    pub current: u64,   // current usage
    pub swap_current: u64,
    pub peak: u64,      // peak usage ever
    pub oom_group: bool, // kill entire group on OOM
    pub events_high: u64,
    pub events_max: u64,
    pub events_oom: u64,
    pub events_oom_kill: u64,
}

impl MemoryController {
    pub const fn new() -> Self {
        Self {
            min: 0, low: 0,
            high: u64::MAX, max: u64::MAX,
            swap_max: u64::MAX,
            current: 0, swap_current: 0, peak: 0,
            oom_group: false,
            events_high: 0, events_max: 0,
            events_oom: 0, events_oom_kill: 0,
        }
    }

    pub fn charge(&mut self, bytes: u64) -> bool {
        let new = self.current.saturating_add(bytes);
        if new > self.max { 
            self.events_max += 1;
            return false; 
        }
        self.current = new;
        if new > self.peak { self.peak = new; }
        if new > self.high { self.events_high += 1; }
        true
    }

    pub fn uncharge(&mut self, bytes: u64) {
        self.current = self.current.saturating_sub(bytes);
    }

    pub fn is_under_pressure(&self) -> bool {
        self.current > self.low
    }
}

// ---------------------------------------------------------------------------
// CPU controller
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct CpuController {
    pub weight: u32,       // 1-10000, default 100
    pub weight_nice: i32,  // -20 to 19
    pub max_us: u64,       // max bandwidth per period (microseconds)
    pub period_us: u64,    // period (default 100ms)
    pub burst_us: u64,     // burst spare bandwidth
    pub usage_total: u64,  // total CPU time used (ns)
    pub usage_user: u64,   // user CPU time (ns)
    pub usage_system: u64, // system CPU time (ns)
    pub nr_periods: u64,
    pub nr_throttled: u64,
    pub throttled_time: u64,
}

impl CpuController {
    pub const fn new() -> Self {
        Self {
            weight: 100,
            weight_nice: 0,
            max_us: u64::MAX,
            period_us: 100_000,
            burst_us: 0,
            usage_total: 0, usage_user: 0, usage_system: 0,
            nr_periods: 0, nr_throttled: 0, throttled_time: 0,
        }
    }

    pub fn is_throttled(&self) -> bool {
        if self.max_us == u64::MAX { return false; }
        // Check if usage in current period exceeds max
        let usage_in_period = self.usage_total % self.period_us;
        usage_in_period >= self.max_us
    }

    pub fn account(&mut self, ns: u64, is_user: bool) {
        self.usage_total += ns;
        if is_user { self.usage_user += ns; }
        else { self.usage_system += ns; }
    }
}

// ---------------------------------------------------------------------------
// IO controller
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct IoDeviceLimit {
    pub major: u32,
    pub minor: u32,
    pub rbps: u64,    // read bytes per second
    pub wbps: u64,    // write bytes per second
    pub riops: u32,   // read IOPS
    pub wiops: u32,   // write IOPS
    pub active: bool,
}

impl IoDeviceLimit {
    pub const fn new() -> Self {
        Self {
            major: 0, minor: 0,
            rbps: u64::MAX, wbps: u64::MAX,
            riops: u32::MAX, wiops: u32::MAX,
            active: false,
        }
    }
}

#[derive(Clone, Copy)]
pub struct IoController {
    pub weight: u16,     // 1-10000, default 100
    pub device_limits: [IoDeviceLimit; MAX_IO_DEVICES],
    pub device_count: u8,
    pub stat_rbytes: u64,
    pub stat_wbytes: u64,
    pub stat_rios: u64,
    pub stat_wios: u64,
}

impl IoController {
    pub const fn new() -> Self {
        Self {
            weight: 100,
            device_limits: [const { IoDeviceLimit::new() }; MAX_IO_DEVICES],
            device_count: 0,
            stat_rbytes: 0, stat_wbytes: 0,
            stat_rios: 0, stat_wios: 0,
        }
    }

    pub fn add_limit(&mut self, major: u32, minor: u32) -> Option<u8> {
        if self.device_count as usize >= MAX_IO_DEVICES { return None; }
        let idx = self.device_count;
        self.device_limits[idx as usize].major = major;
        self.device_limits[idx as usize].minor = minor;
        self.device_limits[idx as usize].active = true;
        self.device_count += 1;
        Some(idx)
    }
}

// ---------------------------------------------------------------------------
// PIDs controller
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct PidsController {
    pub max: u32,        // 0 = unlimited
    pub current: u32,
    pub events_max: u64, // times max was hit
}

impl PidsController {
    pub const fn new() -> Self {
        Self { max: 0, current: 0, events_max: 0 }
    }

    pub fn can_fork(&self) -> bool {
        if self.max == 0 { return true; }
        self.current < self.max
    }

    pub fn charge(&mut self) -> bool {
        if !self.can_fork() { self.events_max += 1; return false; }
        self.current += 1;
        true
    }

    pub fn uncharge(&mut self) {
        if self.current > 0 { self.current -= 1; }
    }
}

// ---------------------------------------------------------------------------
// Cpuset controller
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct CpusetController {
    pub cpus: u64,           // bitmask of allowed CPUs
    pub mems: u64,           // bitmask of allowed NUMA nodes
    pub cpu_exclusive: bool, // exclusive CPU assignment
    pub mem_exclusive: bool,
    pub partition: u8,       // 0=member, 1=root, 2=isolated
    pub effective_cpus: u64,
    pub effective_mems: u64,
}

impl CpusetController {
    pub const fn new() -> Self {
        Self {
            cpus: u64::MAX, mems: u64::MAX,
            cpu_exclusive: false, mem_exclusive: false,
            partition: 0,
            effective_cpus: u64::MAX, effective_mems: u64::MAX,
        }
    }

    pub fn is_cpu_allowed(&self, cpu: u8) -> bool {
        if cpu >= 64 { return false; }
        (self.effective_cpus & (1u64 << cpu as u64)) != 0
    }

    pub fn is_mem_allowed(&self, node: u8) -> bool {
        if node >= 64 { return false; }
        (self.effective_mems & (1u64 << node as u64)) != 0
    }
}

// ---------------------------------------------------------------------------
// PSI (Pressure Stall Information)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct PsiStats {
    pub some_avg10: u32,   // percentage * 100
    pub some_avg60: u32,
    pub some_avg300: u32,
    pub some_total_us: u64,
    pub full_avg10: u32,
    pub full_avg60: u32,
    pub full_avg300: u32,
    pub full_total_us: u64,
}

impl PsiStats {
    pub const fn new() -> Self {
        Self {
            some_avg10: 0, some_avg60: 0, some_avg300: 0, some_total_us: 0,
            full_avg10: 0, full_avg60: 0, full_avg300: 0, full_total_us: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Freezer state
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum FreezerState {
    Thawed  = 0,
    Frozen  = 1,
    Freezing = 2,
}

// ---------------------------------------------------------------------------
// Cgroup
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct Cgroup {
    pub id: u32,
    pub parent_id: u32,
    pub name: [u8; 64],
    pub name_len: u8,
    pub depth: u8,

    // Controllers enabled in this cgroup
    pub controllers: u32,        // bitmask of enabled controllers
    pub subtree_control: u32,    // controllers delegated to children

    // Controller instances
    pub memory: MemoryController,
    pub cpu: CpuController,
    pub io: IoController,
    pub pids: PidsController,
    pub cpuset: CpusetController,

    // PSI
    pub psi_cpu: PsiStats,
    pub psi_memory: PsiStats,
    pub psi_io: PsiStats,

    // Processes in this cgroup
    pub procs: [u32; MAX_PROCS],
    pub proc_count: u16,

    // Children
    pub children: [u32; MAX_CHILDREN],
    pub child_count: u8,

    // State
    pub freezer: FreezerState,
    pub threaded: bool,
    pub populated: bool,
    pub active: bool,
    pub nr_dying_descendants: u32,
}

impl Cgroup {
    pub const fn new() -> Self {
        Self {
            id: 0, parent_id: 0,
            name: [0u8; 64], name_len: 0,
            depth: 0,
            controllers: 0,
            subtree_control: 0,
            memory: MemoryController::new(),
            cpu: CpuController::new(),
            io: IoController::new(),
            pids: PidsController::new(),
            cpuset: CpusetController::new(),
            psi_cpu: PsiStats::new(),
            psi_memory: PsiStats::new(),
            psi_io: PsiStats::new(),
            procs: [0u32; MAX_PROCS],
            proc_count: 0,
            children: [0u32; MAX_CHILDREN],
            child_count: 0,
            freezer: FreezerState::Thawed,
            threaded: false,
            populated: false,
            active: false,
            nr_dying_descendants: 0,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = if n.len() > 63 { 63 } else { n.len() };
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn add_proc(&mut self, pid: u32) -> bool {
        if self.proc_count as usize >= MAX_PROCS { return false; }
        // Check for duplicate
        for i in 0..self.proc_count as usize {
            if self.procs[i] == pid { return true; }
        }
        self.procs[self.proc_count as usize] = pid;
        self.proc_count += 1;
        self.populated = true;
        // Charge pids controller
        if self.controllers & CTRL_PIDS != 0 {
            if !self.pids.charge() { 
                self.proc_count -= 1;
                return false; 
            }
        }
        true
    }

    pub fn remove_proc(&mut self, pid: u32) -> bool {
        for i in 0..self.proc_count as usize {
            if self.procs[i] == pid {
                let mut j = i;
                while j + 1 < self.proc_count as usize {
                    self.procs[j] = self.procs[j + 1];
                    j += 1;
                }
                self.proc_count -= 1;
                if self.controllers & CTRL_PIDS != 0 {
                    self.pids.uncharge();
                }
                self.populated = self.proc_count > 0 || self.child_count > 0;
                return true;
            }
        }
        false
    }

    pub fn add_child(&mut self, child_id: u32) -> bool {
        if self.child_count as usize >= MAX_CHILDREN { return false; }
        self.children[self.child_count as usize] = child_id;
        self.child_count += 1;
        self.populated = true;
        true
    }
}

// ---------------------------------------------------------------------------
// Cgroup hierarchy manager
// ---------------------------------------------------------------------------

pub struct CgroupManager {
    cgroups: [Cgroup; MAX_CGROUPS],
    cgroup_count: u32,
    next_id: u32,
    initialized: bool,
}

impl CgroupManager {
    pub const fn new() -> Self {
        Self {
            cgroups: [const { Cgroup::new() }; MAX_CGROUPS],
            cgroup_count: 0,
            next_id: 1,
            initialized: false,
        }
    }

    /// Initialize with root cgroup
    pub fn init(&mut self) {
        if self.initialized { return; }
        // Create root cgroup
        self.cgroups[0] = Cgroup::new();
        self.cgroups[0].id = self.next_id;
        self.cgroups[0].set_name(b"/");
        self.cgroups[0].controllers = CTRL_ALL;
        self.cgroups[0].subtree_control = CTRL_ALL;
        self.cgroups[0].active = true;
        self.cgroup_count = 1;
        self.next_id += 1;
        self.initialized = true;
    }

    /// Create a child cgroup
    pub fn mkdir(&mut self, parent_id: u32, name: &[u8]) -> Option<u32> {
        if self.cgroup_count as usize >= MAX_CGROUPS { return None; }

        // Find parent
        let parent_idx = self.find_idx(parent_id)?;
        let parent_depth = self.cgroups[parent_idx].depth;
        let parent_subtree = self.cgroups[parent_idx].subtree_control;

        let id = self.next_id;
        self.next_id += 1;

        for i in 0..MAX_CGROUPS {
            if !self.cgroups[i].active {
                self.cgroups[i] = Cgroup::new();
                self.cgroups[i].id = id;
                self.cgroups[i].parent_id = parent_id;
                self.cgroups[i].set_name(name);
                self.cgroups[i].depth = parent_depth + 1;
                self.cgroups[i].controllers = parent_subtree;
                self.cgroups[i].active = true;
                self.cgroup_count += 1;

                // Add to parent
                self.cgroups[parent_idx].add_child(id);

                return Some(id);
            }
        }
        None
    }

    /// Remove a cgroup (must be empty)
    pub fn rmdir(&mut self, cg_id: u32) -> bool {
        if let Some(idx) = self.find_idx(cg_id) {
            if self.cgroups[idx].proc_count > 0 { return false; }
            if self.cgroups[idx].child_count > 0 { return false; }

            let parent_id = self.cgroups[idx].parent_id;
            self.cgroups[idx].active = false;
            self.cgroup_count -= 1;

            // Remove from parent
            if let Some(pidx) = self.find_idx(parent_id) {
                for j in 0..self.cgroups[pidx].child_count as usize {
                    if self.cgroups[pidx].children[j] == cg_id {
                        let mut k = j;
                        while k + 1 < self.cgroups[pidx].child_count as usize {
                            self.cgroups[pidx].children[k] = self.cgroups[pidx].children[k + 1];
                            k += 1;
                        }
                        self.cgroups[pidx].child_count -= 1;
                        break;
                    }
                }
            }
            return true;
        }
        false
    }

    /// Migrate a process between cgroups
    pub fn migrate(&mut self, pid: u32, from_id: u32, to_id: u32) -> bool {
        let from_idx = match self.find_idx(from_id) { Some(i) => i, None => return false };
        let to_idx = match self.find_idx(to_id) { Some(i) => i, None => return false };

        if !self.cgroups[from_idx].remove_proc(pid) { return false; }
        if !self.cgroups[to_idx].add_proc(pid) {
            // Rollback
            self.cgroups[from_idx].add_proc(pid);
            return false;
        }
        true
    }

    /// Set subtree_control (enable/disable controllers for children)
    pub fn set_subtree_control(&mut self, cg_id: u32, enable: u32, disable: u32) -> bool {
        if let Some(idx) = self.find_idx(cg_id) {
            self.cgroups[idx].subtree_control |= enable;
            self.cgroups[idx].subtree_control &= !disable;
            return true;
        }
        false
    }

    /// Freeze a cgroup and descendants
    pub fn freeze(&mut self, cg_id: u32) -> bool {
        if let Some(idx) = self.find_idx(cg_id) {
            self.cgroups[idx].freezer = FreezerState::Frozen;
            // Recursively freeze children
            for c in 0..self.cgroups[idx].child_count as usize {
                let child_id = self.cgroups[idx].children[c];
                self.freeze(child_id);
            }
            return true;
        }
        false
    }

    /// Thaw a cgroup and descendants
    pub fn thaw(&mut self, cg_id: u32) -> bool {
        if let Some(idx) = self.find_idx(cg_id) {
            self.cgroups[idx].freezer = FreezerState::Thawed;
            for c in 0..self.cgroups[idx].child_count as usize {
                let child_id = self.cgroups[idx].children[c];
                self.thaw(child_id);
            }
            return true;
        }
        false
    }

    fn find_idx(&self, id: u32) -> Option<usize> {
        for i in 0..MAX_CGROUPS {
            if self.cgroups[i].active && self.cgroups[i].id == id {
                return Some(i);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Global instance
// ---------------------------------------------------------------------------

static mut CGROUP_MGR: CgroupManager = CgroupManager::new();

fn cgroup_mgr() -> &'static mut CgroupManager {
    unsafe { &mut CGROUP_MGR }
}

// ---------------------------------------------------------------------------
// FFI exports
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn zxyphor_cgroup_init() -> i32 {
    cgroup_mgr().init();
    0
}

#[no_mangle]
pub extern "C" fn zxyphor_cgroup_mkdir(parent_id: u32, name_ptr: *const u8, name_len: u32) -> i32 {
    if name_ptr.is_null() { return -1; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    match cgroup_mgr().mkdir(parent_id, name) {
        Some(id) => id as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_cgroup_rmdir(cg_id: u32) -> i32 {
    if cgroup_mgr().rmdir(cg_id) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn zxyphor_cgroup_add_proc(cg_id: u32, pid: u32) -> i32 {
    if let Some(idx) = cgroup_mgr().find_idx(cg_id) {
        if cgroup_mgr().cgroups[idx].add_proc(pid) { return 0; }
    }
    -1
}

#[no_mangle]
pub extern "C" fn zxyphor_cgroup_set_memory_max(cg_id: u32, max_bytes: u64) -> i32 {
    if let Some(idx) = cgroup_mgr().find_idx(cg_id) {
        cgroup_mgr().cgroups[idx].memory.max = max_bytes;
        return 0;
    }
    -1
}

#[no_mangle]
pub extern "C" fn zxyphor_cgroup_set_cpu_weight(cg_id: u32, weight: u32) -> i32 {
    if weight < 1 || weight > 10000 { return -22; }
    if let Some(idx) = cgroup_mgr().find_idx(cg_id) {
        cgroup_mgr().cgroups[idx].cpu.weight = weight;
        return 0;
    }
    -1
}

#[no_mangle]
pub extern "C" fn zxyphor_cgroup_set_pids_max(cg_id: u32, max_pids: u32) -> i32 {
    if let Some(idx) = cgroup_mgr().find_idx(cg_id) {
        cgroup_mgr().cgroups[idx].pids.max = max_pids;
        return 0;
    }
    -1
}

#[no_mangle]
pub extern "C" fn zxyphor_cgroup_freeze(cg_id: u32) -> i32 {
    if cgroup_mgr().freeze(cg_id) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn zxyphor_cgroup_count() -> u32 {
    cgroup_mgr().cgroup_count
}
