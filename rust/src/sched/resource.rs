// =============================================================================
// Kernel Zxyphor — Resource Control (Cgroup-like)
// =============================================================================
// Hierarchical resource control:
//   - CPU bandwidth limiting (CFS bandwidth control)
//   - Memory limit enforcement with soft/hard limits
//   - I/O bandwidth throttling (BPS and IOPS limits)
//   - PID limits
//   - CPU accounting with per-cgroup stats
//   - OOM killer integration with priority scoring
//   - Hierarchical accounting (child resources count toward parent)
//   - Freezer support (pause/resume all tasks in a group)
// =============================================================================

use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};

pub const MAX_CGROUPS: usize = 128;
pub const MAX_TASKS_PER_GROUP: usize = 64;
pub const MAX_CHILDREN: usize = 16;
pub const CGROUP_NAME_LEN: usize = 32;

// =============================================================================
// CPU bandwidth controller
// =============================================================================

pub struct CpuBandwidth {
    pub quota_us: i64,        // -1 = unlimited, else microseconds per period
    pub period_us: u64,       // Default 100ms
    pub runtime_remaining: i64,
    pub nr_periods: u64,
    pub nr_throttled: u64,
    pub throttled_time_ns: u64,
    pub burst_us: u64,        // Burst capacity
    pub burst_remaining: u64,
    pub weight: u32,          // CPU weight (1-10000, default 100)
}

impl CpuBandwidth {
    pub const fn new() -> Self {
        Self {
            quota_us: -1,
            period_us: 100_000,
            runtime_remaining: 0,
            nr_periods: 0,
            nr_throttled: 0,
            throttled_time_ns: 0,
            burst_us: 0,
            burst_remaining: 0,
            weight: 100,
        }
    }

    /// Check if task can run (has remaining quota)
    pub fn charge_runtime(&mut self, delta_us: u64) -> bool {
        if self.quota_us < 0 {
            return true; // Unlimited
        }
        if self.runtime_remaining >= delta_us as i64 {
            self.runtime_remaining -= delta_us as i64;
            true
        } else if self.burst_remaining >= delta_us {
            self.burst_remaining -= delta_us;
            true
        } else {
            self.nr_throttled += 1;
            false
        }
    }

    /// Period timer: refill runtime
    pub fn refill(&mut self) {
        self.nr_periods += 1;
        if self.quota_us >= 0 {
            self.runtime_remaining = self.quota_us;
            // Refill burst from leftover
            let unused = self.runtime_remaining.max(0) as u64;
            self.burst_remaining = (self.burst_remaining + unused).min(self.burst_us);
        }
    }
}

// =============================================================================
// Memory controller
// =============================================================================

pub struct MemoryController {
    pub limit_bytes: u64,          // Hard limit (OOM if exceeded)
    pub soft_limit_bytes: u64,     // Soft limit (reclaim pressure)
    pub swap_limit_bytes: u64,
    pub usage_bytes: u64,
    pub max_usage_bytes: u64,      // High watermark
    pub swap_usage_bytes: u64,
    pub cache_bytes: u64,          // Page cache usage
    pub rss_bytes: u64,            // Resident set
    pub nr_page_faults: u64,
    pub nr_major_faults: u64,
    pub nr_oom_kills: u32,
    pub oom_kill_disable: bool,
    pub under_oom: bool,
    pub high_bytes: u64,           // Memory.high (throttle point)
    pub low_bytes: u64,            // Memory.low (protection)
    pub min_bytes: u64,            // Memory.min (guaranteed minimum)
}

impl MemoryController {
    pub const fn new() -> Self {
        Self {
            limit_bytes: u64::MAX,
            soft_limit_bytes: u64::MAX,
            swap_limit_bytes: u64::MAX,
            usage_bytes: 0,
            max_usage_bytes: 0,
            swap_usage_bytes: 0,
            cache_bytes: 0,
            rss_bytes: 0,
            nr_page_faults: 0,
            nr_major_faults: 0,
            nr_oom_kills: 0,
            oom_kill_disable: false,
            under_oom: false,
            high_bytes: u64::MAX,
            low_bytes: 0,
            min_bytes: 0,
        }
    }

    /// Try to charge memory allocation
    pub fn charge(&mut self, bytes: u64) -> bool {
        if self.usage_bytes + bytes > self.limit_bytes {
            self.under_oom = true;
            return false;
        }
        self.usage_bytes += bytes;
        self.rss_bytes += bytes;
        if self.usage_bytes > self.max_usage_bytes {
            self.max_usage_bytes = self.usage_bytes;
        }
        true
    }

    /// Uncharge memory
    pub fn uncharge(&mut self, bytes: u64) {
        self.usage_bytes = self.usage_bytes.saturating_sub(bytes);
        self.rss_bytes = self.rss_bytes.saturating_sub(bytes);
        if self.usage_bytes < self.limit_bytes {
            self.under_oom = false;
        }
    }

    /// Whether memory usage is under pressure
    pub fn under_pressure(&self) -> bool {
        self.usage_bytes > self.soft_limit_bytes
            || self.usage_bytes > self.high_bytes
    }

    /// Memory pressure ratio (0-100)
    pub fn pressure_pct(&self) -> u32 {
        if self.limit_bytes == 0 || self.limit_bytes == u64::MAX { return 0; }
        ((self.usage_bytes as u128 * 100) / self.limit_bytes as u128) as u32
    }

    /// OOM killer score for a task in this cgroup
    pub fn oom_score(&self, task_rss_bytes: u64) -> u32 {
        if self.limit_bytes == 0 || self.limit_bytes == u64::MAX { return 0; }
        ((task_rss_bytes as u128 * 1000) / self.limit_bytes as u128) as u32
    }
}

// =============================================================================
// I/O bandwidth controller
// =============================================================================

pub struct IoBandwidth {
    pub read_bps_limit: u64,       // 0 = unlimited
    pub write_bps_limit: u64,
    pub read_iops_limit: u64,
    pub write_iops_limit: u64,
    pub read_bytes: AtomicU64,
    pub write_bytes: AtomicU64,
    pub read_ios: AtomicU64,
    pub write_ios: AtomicU64,
    pub read_bytes_window: u64,
    pub write_bytes_window: u64,
    pub read_ios_window: u64,
    pub write_ios_window: u64,
    pub window_start_ns: u64,
    pub throttled_reads: u64,
    pub throttled_writes: u64,
    pub weight: u16,               // IO weight (1-10000, default 100)
}

impl IoBandwidth {
    pub const fn new() -> Self {
        Self {
            read_bps_limit: 0,
            write_bps_limit: 0,
            read_iops_limit: 0,
            write_iops_limit: 0,
            read_bytes: AtomicU64::new(0),
            write_bytes: AtomicU64::new(0),
            read_ios: AtomicU64::new(0),
            write_ios: AtomicU64::new(0),
            read_bytes_window: 0,
            write_bytes_window: 0,
            read_ios_window: 0,
            write_ios_window: 0,
            window_start_ns: 0,
            throttled_reads: 0,
            throttled_writes: 0,
            weight: 100,
        }
    }

    /// Check if a read operation is allowed
    pub fn check_read(&mut self, bytes: u64, now_ns: u64) -> bool {
        self.maybe_reset_window(now_ns);
        if self.read_bps_limit > 0 && self.read_bytes_window + bytes > self.read_bps_limit {
            self.throttled_reads += 1;
            return false;
        }
        if self.read_iops_limit > 0 && self.read_ios_window + 1 > self.read_iops_limit {
            self.throttled_reads += 1;
            return false;
        }
        self.read_bytes_window += bytes;
        self.read_ios_window += 1;
        self.read_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.read_ios.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Check if a write operation is allowed
    pub fn check_write(&mut self, bytes: u64, now_ns: u64) -> bool {
        self.maybe_reset_window(now_ns);
        if self.write_bps_limit > 0 && self.write_bytes_window + bytes > self.write_bps_limit {
            self.throttled_writes += 1;
            return false;
        }
        if self.write_iops_limit > 0 && self.write_ios_window + 1 > self.write_iops_limit {
            self.throttled_writes += 1;
            return false;
        }
        self.write_bytes_window += bytes;
        self.write_ios_window += 1;
        self.write_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.write_ios.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn maybe_reset_window(&mut self, now_ns: u64) {
        // Reset per-second window
        if now_ns - self.window_start_ns >= 1_000_000_000 {
            self.read_bytes_window = 0;
            self.write_bytes_window = 0;
            self.read_ios_window = 0;
            self.write_ios_window = 0;
            self.window_start_ns = now_ns;
        }
    }
}

// =============================================================================
// PID controller
// =============================================================================

pub struct PidController {
    pub limit: u32,
    pub current: AtomicU32,
}

impl PidController {
    pub const fn new() -> Self {
        Self {
            limit: u32::MAX,
            current: AtomicU32::new(0),
        }
    }

    pub fn charge(&self) -> bool {
        let cur = self.current.load(Ordering::Relaxed);
        if cur >= self.limit { return false; }
        self.current.store(cur + 1, Ordering::Relaxed);
        true
    }

    pub fn uncharge(&self) {
        let cur = self.current.load(Ordering::Relaxed);
        if cur > 0 {
            self.current.store(cur - 1, Ordering::Relaxed);
        }
    }
}

// =============================================================================
// Cgroup (resource group)
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CgroupState {
    Invalid = 0,
    Active = 1,
    Frozen = 2,
    ThawRequested = 3,
}

pub struct Cgroup {
    pub id: u32,
    pub name: [u8; CGROUP_NAME_LEN],
    pub name_len: usize,
    pub parent_id: u32,
    pub children: [u32; MAX_CHILDREN],
    pub nr_children: u32,
    pub tasks: [u32; MAX_TASKS_PER_GROUP],
    pub nr_tasks: u32,
    pub state: CgroupState,

    pub cpu: CpuBandwidth,
    pub memory: MemoryController,
    pub io: IoBandwidth,
    pub pids: PidController,

    // Accounting
    pub cpu_usage_ns: AtomicU64,
    pub creation_time_ns: u64,
    pub nr_descendants: u32,  // Total tasks in subtree
}

impl Cgroup {
    pub const fn new() -> Self {
        Self {
            id: 0,
            name: [0u8; CGROUP_NAME_LEN],
            name_len: 0,
            parent_id: 0,
            children: [0u32; MAX_CHILDREN],
            nr_children: 0,
            tasks: [0u32; MAX_TASKS_PER_GROUP],
            nr_tasks: 0,
            state: CgroupState::Invalid,
            cpu: CpuBandwidth::new(),
            memory: MemoryController::new(),
            io: IoBandwidth::new(),
            pids: PidController::new(),
            cpu_usage_ns: AtomicU64::new(0),
            creation_time_ns: 0,
            nr_descendants: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(CGROUP_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn add_task(&mut self, pid: u32) -> bool {
        if self.nr_tasks as usize >= MAX_TASKS_PER_GROUP { return false; }
        if !self.pids.charge() { return false; }
        self.tasks[self.nr_tasks as usize] = pid;
        self.nr_tasks += 1;
        true
    }

    pub fn remove_task(&mut self, pid: u32) {
        for i in 0..self.nr_tasks as usize {
            if self.tasks[i] == pid {
                for j in i..(self.nr_tasks as usize - 1) {
                    self.tasks[j] = self.tasks[j + 1];
                }
                self.nr_tasks -= 1;
                self.pids.uncharge();
                return;
            }
        }
    }

    pub fn has_task(&self, pid: u32) -> bool {
        self.tasks[..self.nr_tasks as usize].contains(&pid)
    }

    pub fn freeze(&mut self) {
        self.state = CgroupState::Frozen;
    }

    pub fn thaw(&mut self) {
        self.state = CgroupState::Active;
    }
}

// =============================================================================
// Cgroup hierarchy manager
// =============================================================================

pub struct CgroupManager {
    pub groups: [Cgroup; MAX_CGROUPS],
    pub count: usize,
    pub next_id: u32,
}

impl CgroupManager {
    pub const fn new() -> Self {
        Self {
            groups: [const { Cgroup::new() }; MAX_CGROUPS],
            count: 0,
            next_id: 1,
        }
    }

    /// Create root cgroup
    pub fn init(&mut self) {
        self.groups[0].id = 0;
        self.groups[0].state = CgroupState::Active;
        self.groups[0].set_name(b"/");
        self.count = 1;
    }

    /// Create a new cgroup under parent
    pub fn create(&mut self, parent_id: u32, name: &[u8]) -> Option<u32> {
        if self.count >= MAX_CGROUPS { return None; }

        let parent_idx = self.find_index(parent_id)?;
        if self.groups[parent_idx].nr_children as usize >= MAX_CHILDREN { return None; }

        let id = self.next_id;
        self.next_id += 1;

        let idx = self.count;
        self.groups[idx] = Cgroup::new();
        self.groups[idx].id = id;
        self.groups[idx].parent_id = parent_id;
        self.groups[idx].state = CgroupState::Active;
        self.groups[idx].set_name(name);
        self.count += 1;

        // Register as child of parent
        let child_count = self.groups[parent_idx].nr_children as usize;
        self.groups[parent_idx].children[child_count] = id;
        self.groups[parent_idx].nr_children += 1;

        Some(id)
    }

    /// Attach a task to a cgroup (migrate from current cgroup)
    pub fn attach_task(&mut self, cgroup_id: u32, pid: u32) -> bool {
        // Remove from any existing cgroup
        for i in 0..self.count {
            if self.groups[i].has_task(pid) {
                self.groups[i].remove_task(pid);
                break;
            }
        }

        // Add to target cgroup
        if let Some(idx) = self.find_index(cgroup_id) {
            self.groups[idx].add_task(pid)
        } else {
            false
        }
    }

    /// Set CPU quota for a cgroup
    pub fn set_cpu_quota(&mut self, cgroup_id: u32, quota_us: i64, period_us: u64) -> bool {
        if let Some(idx) = self.find_index(cgroup_id) {
            self.groups[idx].cpu.quota_us = quota_us;
            if period_us > 0 {
                self.groups[idx].cpu.period_us = period_us;
            }
            true
        } else {
            false
        }
    }

    /// Set memory limit for a cgroup
    pub fn set_memory_limit(&mut self, cgroup_id: u32, limit_bytes: u64) -> bool {
        if let Some(idx) = self.find_index(cgroup_id) {
            self.groups[idx].memory.limit_bytes = limit_bytes;
            true
        } else {
            false
        }
    }

    /// Set I/O bandwidth limits
    pub fn set_io_limits(
        &mut self, cgroup_id: u32,
        read_bps: u64, write_bps: u64,
        read_iops: u64, write_iops: u64,
    ) -> bool {
        if let Some(idx) = self.find_index(cgroup_id) {
            self.groups[idx].io.read_bps_limit = read_bps;
            self.groups[idx].io.write_bps_limit = write_bps;
            self.groups[idx].io.read_iops_limit = read_iops;
            self.groups[idx].io.write_iops_limit = write_iops;
            true
        } else {
            false
        }
    }

    /// Set PID limit
    pub fn set_pid_limit(&mut self, cgroup_id: u32, limit: u32) -> bool {
        if let Some(idx) = self.find_index(cgroup_id) {
            self.groups[idx].pids.limit = limit;
            true
        } else {
            false
        }
    }

    /// Get memory stats
    pub fn memory_usage(&self, cgroup_id: u32) -> Option<(u64, u64)> {
        let idx = self.find_index(cgroup_id)?;
        Some((
            self.groups[idx].memory.usage_bytes,
            self.groups[idx].memory.limit_bytes,
        ))
    }

    /// Charge memory to task's cgroup
    pub fn charge_memory(&mut self, pid: u32, bytes: u64) -> bool {
        for i in 0..self.count {
            if self.groups[i].has_task(pid) {
                return self.groups[i].memory.charge(bytes);
            }
        }
        true // Not in any cgroup — allow
    }

    /// Uncharge memory
    pub fn uncharge_memory(&mut self, pid: u32, bytes: u64) {
        for i in 0..self.count {
            if self.groups[i].has_task(pid) {
                self.groups[i].memory.uncharge(bytes);
                return;
            }
        }
    }

    /// Freeze a cgroup (pause all tasks)
    pub fn freeze(&mut self, cgroup_id: u32) -> bool {
        if let Some(idx) = self.find_index(cgroup_id) {
            self.groups[idx].freeze();
            true
        } else {
            false
        }
    }

    /// Thaw a cgroup
    pub fn thaw(&mut self, cgroup_id: u32) -> bool {
        if let Some(idx) = self.find_index(cgroup_id) {
            self.groups[idx].thaw();
            true
        } else {
            false
        }
    }

    /// Find the cgroup that a task belongs to
    pub fn find_task_cgroup(&self, pid: u32) -> Option<u32> {
        for i in 0..self.count {
            if self.groups[i].has_task(pid) {
                return Some(self.groups[i].id);
            }
        }
        None
    }

    fn find_index(&self, id: u32) -> Option<usize> {
        for i in 0..self.count {
            if self.groups[i].id == id && self.groups[i].state != CgroupState::Invalid {
                return Some(i);
            }
        }
        None
    }
}

static mut CGROUP_MGR: CgroupManager = CgroupManager::new();

pub unsafe fn cgroup_manager() -> &'static mut CgroupManager {
    &mut *core::ptr::addr_of_mut!(CGROUP_MGR)
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_cgroup_init() {
    unsafe { cgroup_manager().init(); }
}

#[no_mangle]
pub extern "C" fn zxyphor_cgroup_create(parent_id: u32, name_ptr: *const u8, name_len: usize) -> i32 {
    if name_ptr.is_null() || name_len == 0 { return -1; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len.min(CGROUP_NAME_LEN)) };
    unsafe {
        match cgroup_manager().create(parent_id, name) {
            Some(id) => id as i32,
            None => -1,
        }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_cgroup_attach(cgroup_id: u32, pid: u32) -> i32 {
    unsafe { if cgroup_manager().attach_task(cgroup_id, pid) { 0 } else { -1 } }
}

#[no_mangle]
pub extern "C" fn zxyphor_cgroup_set_cpu_quota(cgroup_id: u32, quota_us: i64, period_us: u64) -> i32 {
    unsafe { if cgroup_manager().set_cpu_quota(cgroup_id, quota_us, period_us) { 0 } else { -1 } }
}

#[no_mangle]
pub extern "C" fn zxyphor_cgroup_set_memory_limit(cgroup_id: u32, limit_bytes: u64) -> i32 {
    unsafe { if cgroup_manager().set_memory_limit(cgroup_id, limit_bytes) { 0 } else { -1 } }
}

#[no_mangle]
pub extern "C" fn zxyphor_cgroup_charge_memory(pid: u32, bytes: u64) -> i32 {
    unsafe { if cgroup_manager().charge_memory(pid, bytes) { 0 } else { -1 } }
}
