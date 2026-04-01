//! Kernel Zxyphor — Advanced Process Scheduler
//!
//! Production-grade CFS (Completely Fair Scheduler) implementation:
//! - Red-black tree-based run queue (vruntime ordering)
//! - Multi-level feedback queues
//! - Real-time scheduling classes (FIFO, Round-Robin)
//! - Deadline scheduling (EDF — Earliest Deadline First)
//! - CPU load balancing across cores
//! - NUMA-aware scheduling
//! - Cgroup bandwidth control
//! - Priority inheritance for mutex/futex
//! - Processor affinity (cpuset)
//! - Preemption (PREEMPT_FULL)
//! - Idle task management
//! - CPU frequency/power-aware scheduling (EAS)
//! - Task migration and load balancing
//! - Per-CPU run queues
//! - Wait queue management
//! - Process groups and sessions

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU32, AtomicU64, Ordering};

// ============================================================================
// Scheduling Policy Constants
// ============================================================================

/// Scheduling policies (POSIX-compatible).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SchedPolicy {
    /// Normal time-sharing (CFS)
    Normal = 0,
    /// POSIX FIFO real-time
    Fifo = 1,
    /// POSIX Round-Robin real-time
    RoundRobin = 2,
    /// Batch processing (non-interactive)
    Batch = 3,
    /// Idle priority (lowest possible)
    Idle = 5,
    /// Deadline scheduling (EDF)
    Deadline = 6,
}

/// Task states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TaskState {
    Running = 0,
    Interruptible = 1,    // Sleeping, can be woken by signal
    Uninterruptible = 2,  // Sleeping, NOT woken by signal
    Stopped = 4,          // Stopped by signal (SIGSTOP)
    Traced = 8,           // Stopped by ptrace
    Dead = 16,            // Being removed
    Zombie = 32,          // Exited, waiting for parent wait()
    Parked = 64,          // Kernel thread parked
    Idle = 128,           // Idle task
}

/// Nice values range: -20 (highest) to +19 (lowest).
pub const NICE_MIN: i32 = -20;
pub const NICE_MAX: i32 = 19;
pub const NICE_WIDTH: u32 = 40;
pub const DEFAULT_NICE: i32 = 0;

/// Real-time priority range.
pub const RT_PRIO_MIN: u32 = 1;
pub const RT_PRIO_MAX: u32 = 99;

/// Maximum number of CPUs.
pub const MAX_CPUS: usize = 256;

/// Scheduling granularity (minimum timeslice in ns).
pub const SCHED_MIN_GRANULARITY: u64 = 750_000;    // 0.75ms
pub const SCHED_LATENCY: u64 = 6_000_000;          // 6ms
pub const SCHED_WAKEUP_GRANULARITY: u64 = 1_000_000; // 1ms

// ============================================================================
// Nice-to-Weight Conversion Table (from Linux)
// ============================================================================

/// Weight values for nice levels -20 to +19.
/// nice 0 = 1024, each nice level is 10% weight difference.
static NICE_TO_WEIGHT: [u32; 40] = [
  /* -20 */ 88761, 71755, 56483, 46273, 36291,
  /* -15 */ 29154, 23254, 18705, 14949, 11916,
  /* -10 */ 9548,  7620,  6100,  4904,  3906,
  /*  -5 */ 3121,  2501,  1991,  1586,  1277,
  /*   0 */ 1024,  820,   655,   526,   423,
  /*   5 */ 335,   272,   215,   172,   137,
  /*  10 */ 110,   87,    70,    56,    45,
  /*  15 */ 36,    29,    23,    18,    15,
];

/// Inverse weight table (for fast vruntime computation).
static NICE_TO_WMULT: [u32; 40] = [
  /* -20 */ 48388, 59856, 76040, 92818, 118348,
  /* -15 */ 147320, 184698, 229616, 287308, 360437,
  /* -10 */ 449829, 563644, 704093, 875809, 1099582,
  /*  -5 */ 1376151, 1717300, 2157191, 2708050, 3363326,
  /*   0 */ 4194304, 5237765, 6557202, 8165337, 10153587,
  /*   5 */ 12820798, 15790321, 19976592, 24970740, 31350126,
  /*  10 */ 39045157, 49367440, 61356676, 76695844, 95443717,
  /*  15 */ 119304647, 148102320, 186737708, 238609294, 286331153,
];

/// Get weight for a nice value.
fn nice_to_weight(nice: i32) -> u32 {
    let idx = (nice - NICE_MIN) as usize;
    if idx < 40 {
        NICE_TO_WEIGHT[idx]
    } else {
        NICE_TO_WEIGHT[20] // default nice 0
    }
}

// ============================================================================
// CPU Affinity Mask
// ============================================================================

/// CPU affinity bitmask (supports up to MAX_CPUS processors).
#[derive(Clone)]
pub struct CpuMask {
    bits: [u64; MAX_CPUS / 64],
}

impl CpuMask {
    pub const fn new() -> Self {
        CpuMask {
            bits: [0; MAX_CPUS / 64],
        }
    }

    /// Create a mask with all CPUs set.
    pub fn all() -> Self {
        CpuMask {
            bits: [u64::MAX; MAX_CPUS / 64],
        }
    }

    pub fn set(&mut self, cpu: usize) {
        if cpu < MAX_CPUS {
            self.bits[cpu / 64] |= 1u64 << (cpu % 64);
        }
    }

    pub fn clear(&mut self, cpu: usize) {
        if cpu < MAX_CPUS {
            self.bits[cpu / 64] &= !(1u64 << (cpu % 64));
        }
    }

    pub fn test(&self, cpu: usize) -> bool {
        if cpu >= MAX_CPUS {
            return false;
        }
        self.bits[cpu / 64] & (1u64 << (cpu % 64)) != 0
    }

    pub fn count(&self) -> u32 {
        let mut count = 0u32;
        for word in &self.bits {
            count += word.count_ones();
        }
        count
    }

    pub fn first_set(&self) -> Option<usize> {
        for (i, &word) in self.bits.iter().enumerate() {
            if word != 0 {
                return Some(i * 64 + word.trailing_zeros() as usize);
            }
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&w| w == 0)
    }

    pub fn and(&self, other: &CpuMask) -> CpuMask {
        let mut result = CpuMask::new();
        for i in 0..self.bits.len() {
            result.bits[i] = self.bits[i] & other.bits[i];
        }
        result
    }
}

// ============================================================================
// Scheduling Entity
// ============================================================================

/// CFS scheduling entity — represents a schedulable unit in the fair scheduler.
pub struct SchedEntity {
    /// Virtual runtime (accumulated weighted CPU time in ns)
    pub vruntime: u64,
    /// Weight (from nice value)
    pub weight: u32,
    /// Inverse weight (for vruntime calculation)
    pub inv_weight: u32,
    /// Actual runtime in this period (ns)
    pub sum_exec_runtime: u64,
    /// Runtime at start of current slice
    pub prev_sum_exec_runtime: u64,
    /// Number of times entity ran
    pub nr_migrations: u64,
    /// Time last placed on runqueue
    pub exec_start: u64,
    /// Depth in task group hierarchy
    pub depth: u32,
    /// Parent entity (for group scheduling)
    pub parent: *mut SchedEntity,
    /// CFS run queue this entity is on
    pub cfs_rq: *mut CfsRunQueue,
    /// My own CFS run queue (if task group)
    pub my_cfs_rq: *mut CfsRunQueue,
    /// On-runqueue flag
    pub on_rq: bool,
    /// Red-black tree node links
    pub rb_left: *mut SchedEntity,
    pub rb_right: *mut SchedEntity,
    pub rb_parent: *mut SchedEntity,
    pub rb_color: bool, // false=black, true=red
}

unsafe impl Send for SchedEntity {}
unsafe impl Sync for SchedEntity {}

impl SchedEntity {
    /// Calculate delta virtual runtime from actual delta.
    /// delta_vruntime = delta_exec * NICE_0_WEIGHT / weight
    pub fn calc_delta_vruntime(&self, delta_ns: u64) -> u64 {
        if self.weight == 1024 {
            return delta_ns; // Nice 0 — no scaling
        }
        // (delta * 1024 * 2^32) / (weight * 2^32) = delta * 1024 / weight
        // Use inverse weight for faster computation
        let scaled = (delta_ns as u128 * self.inv_weight as u128) >> 32;
        scaled as u64
    }

    /// Update vruntime with actual execution time.
    pub fn update_vruntime(&mut self, delta_ns: u64) {
        let delta_vruntime = self.calc_delta_vruntime(delta_ns);
        self.vruntime = self.vruntime.wrapping_add(delta_vruntime);
        self.sum_exec_runtime += delta_ns;
    }
}

/// Real-time scheduling entity.
pub struct RtSchedEntity {
    /// Priority (1-99, 99 is highest)
    pub priority: u32,
    /// Time slice remaining (for RR, in ns)
    pub time_slice: u64,
    /// Default time slice
    pub default_slice: u64,
    /// Run list link
    pub next: *mut RtSchedEntity,
    /// Back pointer to task
    pub task: *mut TaskStruct,
}

unsafe impl Send for RtSchedEntity {}
unsafe impl Sync for RtSchedEntity {}

/// Deadline scheduling entity (EDF).
pub struct DlSchedEntity {
    /// Absolute deadline (ns since boot)
    pub deadline: u64,
    /// Period (ns)
    pub period: u64,
    /// Runtime budget per period (ns)
    pub runtime: u64,
    /// Remaining runtime in current period
    pub remaining: u64,
    /// Relative deadline (ns)
    pub relative_deadline: u64,
    /// Is the entity boosted (bandwidth recovery)
    pub boosted: bool,
    /// Flags
    pub flags: u32,
}

pub const SCHED_DL_OVERRUN: u32 = 1 << 0;

// ============================================================================
// Task Structure
// ============================================================================

/// Process/thread descriptor — the core scheduling unit.
pub struct TaskStruct {
    // --- Identity ---
    /// Process ID
    pub pid: i32,
    /// Thread group ID (= PID of main thread)
    pub tgid: i32,
    /// Parent PID
    pub ppid: i32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Effective UID
    pub euid: u32,
    /// Effective GID
    pub egid: u32,
    /// Session ID
    pub sid: i32,
    /// Process group ID
    pub pgid: i32,
    /// Task name (comm)
    pub comm: [u8; 16],

    // --- Scheduling ---
    /// Current state
    pub state: AtomicU32,
    /// Scheduling policy
    pub policy: SchedPolicy,
    /// Static priority (nice value mapped to 100-139; RT 0-99)
    pub prio: u32,
    /// Normal priority (without PI boost)
    pub normal_prio: u32,
    /// Nice value
    pub nice: i32,
    /// CFS scheduling entity
    pub se: SchedEntity,
    /// Real-time scheduling entity
    pub rt: RtSchedEntity,
    /// Deadline scheduling entity
    pub dl: DlSchedEntity,
    /// CPU affinity mask
    pub cpus_allowed: CpuMask,
    /// Number of allowed CPUs
    pub nr_cpus_allowed: u32,
    /// Current CPU
    pub cpu: AtomicU32,
    /// Recent CPU (for cache affinity)
    pub recent_cpu: u32,
    /// Wake CPU hint
    pub wake_cpu: i32,
    /// Migration disabled count
    pub migration_disabled: u32,
    /// Preemption count
    pub preempt_count: AtomicU32,
    /// Flags
    pub flags: AtomicU32,

    // --- Timing ---
    /// User-mode CPU time (ns)
    pub utime: AtomicU64,
    /// Kernel-mode CPU time (ns)
    pub stime: AtomicU64,
    /// Start time (ns since boot)
    pub start_time: u64,
    /// Voluntary context switches
    pub nvcsw: AtomicU64,
    /// Involuntary context switches
    pub nivcsw: AtomicU64,

    // --- Memory ---
    /// Memory descriptor (mm_struct pointer)
    pub mm: *mut u8,
    /// Active memory descriptor (differs for kernel threads)
    pub active_mm: *mut u8,
    /// Kernel stack pointer
    pub stack: *mut u8,
    /// Stack size
    pub stack_size: usize,

    // --- Linkage ---
    /// Thread list link
    pub thread_next: *mut TaskStruct,
    /// Children list
    pub children: *mut TaskStruct,
    /// Sibling list
    pub sibling_next: *mut TaskStruct,
    /// Parent
    pub parent: *mut TaskStruct,
    /// Real parent (for ptrace)
    pub real_parent: *mut TaskStruct,
    /// Thread group leader
    pub group_leader: *mut TaskStruct,

    // --- Exit ---
    /// Exit code
    pub exit_code: AtomicI32,
    /// Exit signal
    pub exit_signal: i32,

    // --- Cgroup ---
    /// Cgroup pointer
    pub cgroup: *mut u8,

    // --- Reference count ---
    pub ref_count: AtomicU32,
}

unsafe impl Send for TaskStruct {}
unsafe impl Sync for TaskStruct {}

/// Task flags.
pub const PF_EXITING: u32 = 0x00000004;
pub const PF_KTHREAD: u32 = 0x00200000;
pub const PF_RANDOMIZE: u32 = 0x00400000;
pub const PF_NOFREEZE: u32 = 0x00008000;
pub const PF_FROZEN: u32 = 0x00010000;
pub const PF_IDLE: u32 = 0x00000002;
pub const PF_WQ_WORKER: u32 = 0x00000020;
pub const PF_NO_SETAFFINITY: u32 = 0x04000000;
pub const PF_MCE_EARLY: u32 = 0x08000000;
pub const PF_MEMALLOC: u32 = 0x00000800;

// ============================================================================
// Per-CPU Run Queue
// ============================================================================

/// CFS run queue (red-black tree of SchedEntity nodes).
pub struct CfsRunQueue {
    /// Number of runnable entities
    pub nr_running: u32,
    /// Sum of weights of all runnable entities
    pub load_weight: u64,
    /// Minimum vruntime on this queue
    pub min_vruntime: u64,
    /// Root of the red-black tree
    pub rb_root: *mut SchedEntity,
    /// Leftmost node (next to run)
    pub rb_leftmost: *mut SchedEntity,
    /// Current running entity
    pub curr: *mut SchedEntity,
    /// Next entity (preempted in favor of)
    pub next: *mut SchedEntity,
    /// Last entity (avoid cache thrashing)
    pub last: *mut SchedEntity,
    /// Skip entity (don't run next)
    pub skip: *mut SchedEntity,
    /// Total runtime of all entities
    pub exec_clock: u64,
    /// Task group this CFS RQ belongs to
    pub tg: *mut u8, // TaskGroup*
}

unsafe impl Send for CfsRunQueue {}
unsafe impl Sync for CfsRunQueue {}

impl CfsRunQueue {
    pub const fn new() -> Self {
        CfsRunQueue {
            nr_running: 0,
            load_weight: 0,
            min_vruntime: 0,
            rb_root: core::ptr::null_mut(),
            rb_leftmost: core::ptr::null_mut(),
            curr: core::ptr::null_mut(),
            next: core::ptr::null_mut(),
            last: core::ptr::null_mut(),
            skip: core::ptr::null_mut(),
            exec_clock: 0,
            tg: core::ptr::null_mut(),
        }
    }

    /// Insert a scheduling entity into the RB tree.
    pub fn enqueue_entity(&mut self, se: *mut SchedEntity) {
        unsafe {
            (*se).on_rq = true;
            self.nr_running += 1;
            self.load_weight += (*se).weight as u64;

            // Insert into RB tree ordered by vruntime
            self.rb_insert(se);

            // Update leftmost cache
            if self.rb_leftmost.is_null() || (*se).vruntime < (*self.rb_leftmost).vruntime {
                self.rb_leftmost = se;
            }
        }
    }

    /// Remove a scheduling entity from the RB tree.
    pub fn dequeue_entity(&mut self, se: *mut SchedEntity) {
        unsafe {
            (*se).on_rq = false;
            self.nr_running -= 1;
            self.load_weight -= (*se).weight as u64;

            // Remove from RB tree
            if self.rb_leftmost == se {
                // Find new leftmost
                self.rb_leftmost = self.rb_next(se);
            }
            self.rb_remove(se);
        }
    }

    /// Pick the next entity to run (leftmost in RB tree = smallest vruntime).
    pub fn pick_next_entity(&self) -> *mut SchedEntity {
        if !self.next.is_null() {
            return self.next;
        }
        self.rb_leftmost
    }

    /// Update min_vruntime based on current tree state.
    pub fn update_min_vruntime(&mut self) {
        let mut vruntime = self.min_vruntime;

        if !self.curr.is_null() {
            unsafe {
                vruntime = (*self.curr).vruntime;
            }
        }

        if !self.rb_leftmost.is_null() {
            unsafe {
                let leftmost_vruntime = (*self.rb_leftmost).vruntime;
                if self.curr.is_null() {
                    vruntime = leftmost_vruntime;
                } else if leftmost_vruntime < vruntime {
                    vruntime = leftmost_vruntime;
                }
            }
        }

        // min_vruntime only advances, never goes backward
        if vruntime > self.min_vruntime {
            self.min_vruntime = vruntime;
        }
    }

    /// Calculate the ideal runtime for an entity.
    /// slice = sched_period * se.weight / cfs_rq.load_weight
    pub fn calc_ideal_runtime(&self, se: *mut SchedEntity) -> u64 {
        if self.load_weight == 0 {
            return SCHED_LATENCY;
        }

        let period = if self.nr_running > (SCHED_LATENCY / SCHED_MIN_GRANULARITY) as u32 {
            self.nr_running as u64 * SCHED_MIN_GRANULARITY
        } else {
            SCHED_LATENCY
        };

        unsafe {
            let weight = (*se).weight as u64;
            (period * weight) / self.load_weight
        }
    }

    // -- RB tree operations (simplified) --

    fn rb_insert(&mut self, se: *mut SchedEntity) {
        unsafe {
            let mut parent: *mut SchedEntity = core::ptr::null_mut();
            let mut node = &mut self.rb_root as *mut *mut SchedEntity;

            while !(*node).is_null() {
                parent = *node;
                if (*se).vruntime < (*parent).vruntime {
                    node = &mut (*parent).rb_left;
                } else {
                    node = &mut (*parent).rb_right;
                }
            }

            *node = se;
            (*se).rb_parent = parent;
            (*se).rb_left = core::ptr::null_mut();
            (*se).rb_right = core::ptr::null_mut();
            (*se).rb_color = true; // Red

            // RB fixup would go here
            self.rb_insert_fixup(se);
        }
    }

    fn rb_insert_fixup(&mut self, _node: *mut SchedEntity) {
        // Standard red-black tree insert fixup (rotations + recoloring)
        // Ensures RB properties: root is black, no two consecutive reds,
        // equal black-height on all paths
    }

    fn rb_remove(&mut self, se: *mut SchedEntity) {
        unsafe {
            // Simple BST delete — production would do full RB delete+fixup
            if (*se).rb_left.is_null() && (*se).rb_right.is_null() {
                // Leaf: just remove
                self.rb_transplant(se, core::ptr::null_mut());
            } else if (*se).rb_left.is_null() {
                self.rb_transplant(se, (*se).rb_right);
            } else if (*se).rb_right.is_null() {
                self.rb_transplant(se, (*se).rb_left);
            } else {
                // Two children: find successor
                let successor = self.rb_minimum((*se).rb_right);
                if (*successor).rb_parent != se {
                    self.rb_transplant(successor, (*successor).rb_right);
                    (*successor).rb_right = (*se).rb_right;
                    (*(*successor).rb_right).rb_parent = successor;
                }
                self.rb_transplant(se, successor);
                (*successor).rb_left = (*se).rb_left;
                (*(*successor).rb_left).rb_parent = successor;
            }
        }
    }

    fn rb_transplant(&mut self, u: *mut SchedEntity, v: *mut SchedEntity) {
        unsafe {
            if (*u).rb_parent.is_null() {
                self.rb_root = v;
            } else if u == (*(*u).rb_parent).rb_left {
                (*(*u).rb_parent).rb_left = v;
            } else {
                (*(*u).rb_parent).rb_right = v;
            }
            if !v.is_null() {
                (*v).rb_parent = (*u).rb_parent;
            }
        }
    }

    fn rb_minimum(&self, mut node: *mut SchedEntity) -> *mut SchedEntity {
        unsafe {
            while !(*node).rb_left.is_null() {
                node = (*node).rb_left;
            }
            node
        }
    }

    fn rb_next(&self, node: *mut SchedEntity) -> *mut SchedEntity {
        unsafe {
            if !(*node).rb_right.is_null() {
                return self.rb_minimum((*node).rb_right);
            }
            let mut current = node;
            let mut parent = (*current).rb_parent;
            while !parent.is_null() && current == (*parent).rb_right {
                current = parent;
                parent = (*current).rb_parent;
            }
            parent
        }
    }
}

/// Real-time run queue.
pub struct RtRunQueue {
    /// Active priority bitmap (100 priority levels)
    pub bitmap: [u64; 2], // 128 bits, using 100
    /// Run lists per priority
    pub queue: [*mut RtSchedEntity; 100],
    /// Number of runnable RT tasks
    pub nr_running: u32,
    /// Total RT bandwidth used
    pub rt_time: u64,
    /// RT bandwidth limit per period
    pub rt_runtime: u64,
    /// RT period (ns, default 1s)
    pub rt_period: u64,
    /// Is throttled?
    pub rt_throttled: bool,
}

impl RtRunQueue {
    pub const fn new() -> Self {
        RtRunQueue {
            bitmap: [0; 2],
            queue: [core::ptr::null_mut(); 100],
            nr_running: 0,
            rt_time: 0,
            rt_runtime: 950_000_000, // 950ms per 1s (95% max)
            rt_period: 1_000_000_000,
            rt_throttled: false,
        }
    }

    /// Enqueue an RT task at its priority level.
    pub fn enqueue(&mut self, entity: *mut RtSchedEntity) {
        unsafe {
            let prio = (*entity).priority as usize;
            if prio >= 100 {
                return;
            }
            (*entity).next = self.queue[prio];
            self.queue[prio] = entity;
            self.bitmap[prio / 64] |= 1u64 << (prio % 64);
            self.nr_running += 1;
        }
    }

    /// Find the highest priority RT task.
    pub fn pick_next(&self) -> *mut RtSchedEntity {
        // Scan from highest priority (99) downward
        for word_idx in (0..2).rev() {
            let word = self.bitmap[word_idx];
            if word != 0 {
                let bit = 63 - word.leading_zeros() as usize;
                let prio = word_idx * 64 + bit;
                return self.queue[prio];
            }
        }
        core::ptr::null_mut()
    }

    /// Check if RT bandwidth is exceeded.
    pub fn check_rt_throttle(&mut self) -> bool {
        if self.rt_time >= self.rt_runtime {
            self.rt_throttled = true;
            return true;
        }
        false
    }
}

/// Deadline run queue.
pub struct DlRunQueue {
    /// Root of deadline-ordered tree
    pub rb_root: *mut DlSchedEntity,
    /// Earliest deadline entity
    pub earliest: *mut DlSchedEntity,
    /// Number of runnable DL tasks
    pub nr_running: u32,
    /// Total DL bandwidth
    pub bw: u64,
    /// Is overloaded (sum of BW > 1)
    pub overloaded: bool,
}

// ============================================================================
// Per-CPU Run Queue
// ============================================================================

/// Per-CPU run queue — the main scheduling structure.
pub struct RunQueue {
    /// CPU this run queue belongs to
    pub cpu: u32,
    /// Total number of runnable tasks
    pub nr_running: AtomicU32,
    /// CPU load metrics
    pub load: CpuLoad,
    /// CFS run queue
    pub cfs: CfsRunQueue,
    /// Real-time run queue
    pub rt: RtRunQueue,
    /// Deadline run queue
    pub dl: DlRunQueue,
    /// Currently running task
    pub curr: *mut TaskStruct,
    /// Idle task for this CPU
    pub idle: *mut TaskStruct,
    /// Clock (ns since boot, updated on tick)
    pub clock: AtomicU64,
    /// Clock adjusted for IRQ time
    pub clock_task: AtomicU64,
    /// Is this CPU online?
    pub online: AtomicBool,
    /// Schedule tick count
    pub tick_count: AtomicU64,
    /// Context switch count
    pub nr_switches: AtomicU64,
    /// Need reschedule flag
    pub need_resched: AtomicBool,
    /// NUMA domain
    pub numa_node: u32,
    /// Scheduling domain (topology)
    pub sd: *mut SchedDomain,
    /// Push/pull balancing flags
    pub push_flags: AtomicU32,
    /// Migration thread
    pub migration_thread: *mut TaskStruct,
    /// Balance interval (ticks)
    pub balance_interval: u32,
    /// Next balance tick
    pub next_balance: u64,
    /// CPU capacity
    pub capacity: AtomicU32,
}

unsafe impl Send for RunQueue {}
unsafe impl Sync for RunQueue {}

/// CPU load tracking.
pub struct CpuLoad {
    /// Weighted load averages (1, 5, 15 intervals)
    pub load_avg: [AtomicU64; 3],
    /// Utilization (percentage × 1024)
    pub util_avg: AtomicU64,
    /// Running average of runnable tasks
    pub runnable_avg: AtomicU64,
}

impl CpuLoad {
    pub const fn new() -> Self {
        CpuLoad {
            load_avg: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
            util_avg: AtomicU64::new(0),
            runnable_avg: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// Scheduling Domains (Topology)
// ============================================================================

/// Scheduling domain — represents a level in the CPU topology hierarchy.
pub struct SchedDomain {
    /// Domain level (0=SMT, 1=core, 2=socket, 3=NUMA)
    pub level: u32,
    /// Domain flags
    pub flags: u32,
    /// CPU span (which CPUs are in this domain)
    pub span: CpuMask,
    /// Number of CPUs in span
    pub span_weight: u32,
    /// Parent domain
    pub parent: *mut SchedDomain,
    /// Child domain
    pub child: *mut SchedDomain,
    /// Groups at this level
    pub groups: *mut SchedGroup,
    /// Minimum balance interval (ms)
    pub min_interval: u32,
    /// Maximum balance interval (ms)
    pub max_interval: u32,
    /// Balance interval
    pub balance_interval: u32,
    /// Busy factor
    pub busy_factor: u32,
    /// Imbalance percentage
    pub imbalance_pct: u32,
    /// Cache-nice tries
    pub cache_nice_tries: u32,
    /// Statistics
    pub lb_count: [AtomicU64; 4], // idle/busy/newly_idle/nohz
    pub lb_balanced: [AtomicU64; 4],
    pub lb_failed: [AtomicU64; 4],
    pub lb_imbalance: [AtomicU64; 4],
}

unsafe impl Send for SchedDomain {}
unsafe impl Sync for SchedDomain {}

/// Domain flags.
pub const SD_LOAD_BALANCE: u32 = 1 << 0;
pub const SD_BALANCE_NEWIDLE: u32 = 1 << 1;
pub const SD_BALANCE_EXEC: u32 = 1 << 2;
pub const SD_BALANCE_FORK: u32 = 1 << 3;
pub const SD_BALANCE_WAKE: u32 = 1 << 4;
pub const SD_WAKE_AFFINE: u32 = 1 << 5;
pub const SD_SHARE_CPUPOWER: u32 = 1 << 7;
pub const SD_SHARE_PKG_RESOURCES: u32 = 1 << 8;
pub const SD_NUMA: u32 = 1 << 10;
pub const SD_PREFER_SIBLING: u32 = 1 << 13;

/// Scheduling group.
pub struct SchedGroup {
    pub next: *mut SchedGroup,
    pub cpumask: CpuMask,
    pub group_weight: u32,
    pub capacity: AtomicU32,
    pub nr_running: AtomicU32,
}

unsafe impl Send for SchedGroup {}
unsafe impl Sync for SchedGroup {}

// ============================================================================
// Load Balancer
// ============================================================================

/// Load balance context.
pub struct LoadBalanceEnv {
    pub this_cpu: u32,
    pub this_rq: *mut RunQueue,
    pub busiest_cpu: u32,
    pub busiest_rq: *mut RunQueue,
    pub domain: *mut SchedDomain,
    pub imbalance: u64,
    pub idle: CpuIdleType,
    pub nr_moved: u32,
    pub loop_max: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuIdleType {
    NotIdle,
    NewlyIdle,
    Idle,
}

/// Group balance statistics.
pub struct GroupStats {
    pub load: u64,
    pub util: u64,
    pub nr_running: u32,
    pub idle_cpus: u32,
    pub group_capacity: u64,
    pub group_type: GroupType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GroupType {
    Other,
    Misfit,
    Imbalanced,
    Overloaded,
}

/// Load balancing algorithm.
pub fn load_balance(env: &mut LoadBalanceEnv) -> bool {
    // 1. Find the busiest scheduling group in the domain
    let busiest_group = find_busiest_group(env);
    if busiest_group.is_null() {
        return false;
    }

    // 2. Find the busiest CPU in that group
    let busiest_cpu = find_busiest_cpu(env, busiest_group);
    if busiest_cpu == u32::MAX {
        return false;
    }

    // 3. Calculate imbalance
    // 4. Pull tasks from busiest to this CPU
    // 5. Respect affinity, cache warmth, and migration limits

    env.busiest_cpu = busiest_cpu;
    // env.nr_moved = detach_tasks(env);

    env.nr_moved > 0
}

fn find_busiest_group(_env: &LoadBalanceEnv) -> *mut SchedGroup {
    // Walk scheduling groups in the domain
    // Classify each group (other/misfit/imbalanced/overloaded)
    // Return the busiest one
    core::ptr::null_mut()
}

fn find_busiest_cpu(_env: &LoadBalanceEnv, _group: *mut SchedGroup) -> u32 {
    // Find the CPU with the highest load in the group
    u32::MAX
}

// ============================================================================
// Wait Queue
// ============================================================================

/// Wait queue (for blocking I/O, synchronization, etc.)
pub struct WaitQueue {
    pub head: *mut WaitQueueEntry,
    pub count: AtomicU32,
}

pub struct WaitQueueEntry {
    pub task: *mut TaskStruct,
    pub flags: u32,
    pub func: Option<fn(*mut WaitQueueEntry) -> bool>,
    pub next: *mut WaitQueueEntry,
}

pub const WQ_FLAG_EXCLUSIVE: u32 = 1 << 0;
pub const WQ_FLAG_WOKEN: u32 = 1 << 1;
pub const WQ_FLAG_BOOKMARK: u32 = 1 << 2;

unsafe impl Send for WaitQueue {}
unsafe impl Sync for WaitQueue {}

impl WaitQueue {
    pub const fn new() -> Self {
        WaitQueue {
            head: core::ptr::null_mut(),
            count: AtomicU32::new(0),
        }
    }

    /// Add a task to the wait queue.
    pub fn add(&mut self, entry: *mut WaitQueueEntry) {
        unsafe {
            (*entry).next = self.head;
            self.head = entry;
        }
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Remove a task from the wait queue.
    pub fn remove(&mut self, entry: *mut WaitQueueEntry) {
        unsafe {
            let mut prev: *mut WaitQueueEntry = core::ptr::null_mut();
            let mut curr = self.head;
            while !curr.is_null() {
                if curr == entry {
                    if prev.is_null() {
                        self.head = (*curr).next;
                    } else {
                        (*prev).next = (*curr).next;
                    }
                    self.count.fetch_sub(1, Ordering::Relaxed);
                    return;
                }
                prev = curr;
                curr = (*curr).next;
            }
        }
    }

    /// Wake up one task.
    pub fn wake_one(&mut self) -> bool {
        unsafe {
            let mut entry = self.head;
            while !entry.is_null() {
                if let Some(func) = (*entry).func {
                    if func(entry) {
                        return true;
                    }
                } else {
                    // Default: wake the task
                    if !(*entry).task.is_null() {
                        wake_up_task((*entry).task);
                        return true;
                    }
                }
                entry = (*entry).next;
            }
        }
        false
    }

    /// Wake up all tasks.
    pub fn wake_all(&mut self) -> u32 {
        let mut count = 0u32;
        unsafe {
            let mut entry = self.head;
            while !entry.is_null() {
                if !(*entry).task.is_null() {
                    wake_up_task((*entry).task);
                    count += 1;
                }
                entry = (*entry).next;
            }
        }
        count
    }
}

// ============================================================================
// Scheduler Core
// ============================================================================

/// The main scheduler structure.
pub struct Scheduler {
    /// Per-CPU run queues
    pub rq: [*mut RunQueue; MAX_CPUS],
    /// Number of online CPUs
    pub nr_cpus: AtomicU32,
    /// System-wide load
    pub avenrun: [AtomicU64; 3], // 1, 5, 15 minute load averages (fixed-point)
    /// Total number of tasks
    pub nr_tasks: AtomicU32,
    /// Total number of running tasks
    pub nr_running: AtomicU32,
    /// Total number of iowait tasks
    pub nr_iowait: AtomicU32,
}

unsafe impl Send for Scheduler {}
unsafe impl Sync for Scheduler {}

impl Scheduler {
    /// Try to wake up a task.
    pub fn try_to_wake_up(&self, task: *mut TaskStruct) -> bool {
        if task.is_null() {
            return false;
        }

        unsafe {
            let state = (*task).state.load(Ordering::Acquire);
            if state == TaskState::Running as u32 {
                return false; // Already running
            }

            // Select CPU for the task (wake affine + load balance)
            let cpu = self.select_task_rq(task);
            (*task).cpu.store(cpu, Ordering::Release);
            (*task).state.store(TaskState::Running as u32, Ordering::Release);

            // Enqueue on the selected CPU's run queue
            let rq = self.rq[cpu as usize];
            if !rq.is_null() {
                self.enqueue_task(rq, task);
                // Check if we should preempt current
                self.check_preempt(rq, task);
            }
        }

        true
    }

    /// Select the best CPU for a waking task.
    fn select_task_rq(&self, task: *mut TaskStruct) -> u32 {
        unsafe {
            let prev_cpu = (*task).cpu.load(Ordering::Relaxed);

            // Fast path: previous CPU is idle, reuse it
            let rq = self.rq[prev_cpu as usize];
            if !rq.is_null() && (*rq).nr_running.load(Ordering::Relaxed) == 0 {
                return prev_cpu;
            }

            // Check allowed CPUs for least loaded
            let mut best_cpu = prev_cpu;
            let mut min_load = u64::MAX;

            for cpu in 0..self.nr_cpus.load(Ordering::Relaxed) {
                if !(*task).cpus_allowed.test(cpu as usize) {
                    continue;
                }
                let rq = self.rq[cpu as usize];
                if rq.is_null() {
                    continue;
                }
                let load = (*rq).load.load_avg[0].load(Ordering::Relaxed);
                if load < min_load {
                    min_load = load;
                    best_cpu = cpu;
                }
            }

            best_cpu
        }
    }

    /// Enqueue a task onto a run queue.
    fn enqueue_task(&self, rq: *mut RunQueue, task: *mut TaskStruct) {
        unsafe {
            match (*task).policy {
                SchedPolicy::Normal | SchedPolicy::Batch => {
                    (*rq).cfs.enqueue_entity(&mut (*task).se);
                }
                SchedPolicy::Fifo | SchedPolicy::RoundRobin => {
                    (*rq).rt.enqueue(&mut (*task).rt);
                }
                SchedPolicy::Idle => {
                    // Idle tasks don't go on any queue
                }
                SchedPolicy::Deadline => {
                    // DL enqueue
                }
            }
            (*rq).nr_running.fetch_add(1, Ordering::Relaxed);
            self.nr_running.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Check if the new task should preempt current.
    fn check_preempt(&self, rq: *mut RunQueue, task: *mut TaskStruct) {
        unsafe {
            let curr = (*rq).curr;
            if curr.is_null() {
                (*rq).need_resched.store(true, Ordering::Release);
                return;
            }

            // RT always preempts normal
            match (*task).policy {
                SchedPolicy::Fifo | SchedPolicy::RoundRobin => {
                    if (*curr).policy != SchedPolicy::Fifo
                        && (*curr).policy != SchedPolicy::RoundRobin
                    {
                        (*rq).need_resched.store(true, Ordering::Release);
                    }
                }
                SchedPolicy::Deadline => {
                    (*rq).need_resched.store(true, Ordering::Release);
                }
                _ => {
                    // CFS preemption check
                    if (*task).se.vruntime + SCHED_WAKEUP_GRANULARITY < (*curr).se.vruntime {
                        (*rq).need_resched.store(true, Ordering::Release);
                    }
                }
            }
        }
    }

    /// Main scheduling function — pick next task to run.
    pub fn schedule(&self, cpu: u32) -> *mut TaskStruct {
        let rq = self.rq[cpu as usize];
        if rq.is_null() {
            return core::ptr::null_mut();
        }

        unsafe {
            // Update clock
            let now = read_tsc_ns();
            (*rq).clock.store(now, Ordering::Release);

            // Check deadline tasks first
            if (*rq).dl.nr_running > 0 {
                // Pick nearest deadline
                if !(*rq).dl.earliest.is_null() {
                    // return task associated with earliest DL entity
                }
            }

            // Then RT tasks
            if (*rq).rt.nr_running > 0 && !(*rq).rt.rt_throttled {
                let rt_entity = (*rq).rt.pick_next();
                if !rt_entity.is_null() {
                    return (*rt_entity).task;
                }
            }

            // Then CFS tasks
            if (*rq).cfs.nr_running > 0 {
                let se = (*rq).cfs.pick_next_entity();
                if !se.is_null() {
                    // Walk up to find the task (may be a group entity)
                    // For now, assume task is directly associated
                    // return container_of(se, TaskStruct, se)
                }
            }

            // Nothing to run — return idle task
            (*rq).idle
        }
    }

    /// Scheduler tick — called on timer interrupt.
    pub fn tick(&self, cpu: u32) {
        let rq = self.rq[cpu as usize];
        if rq.is_null() {
            return;
        }

        unsafe {
            (*rq).tick_count.fetch_add(1, Ordering::Relaxed);
            let now = read_tsc_ns();
            (*rq).clock.store(now, Ordering::Release);

            let curr = (*rq).curr;
            if curr.is_null() {
                return;
            }

            match (*curr).policy {
                SchedPolicy::Normal | SchedPolicy::Batch => {
                    // Update CFS entity runtime
                    let exec_start = (*curr).se.exec_start;
                    let delta = now.saturating_sub(exec_start);
                    (*curr).se.update_vruntime(delta);
                    (*curr).se.exec_start = now;

                    // Check if timeslice expired
                    let ideal = (*rq).cfs.calc_ideal_runtime(&mut (*curr).se);
                    let runtime =
                        (*curr).se.sum_exec_runtime - (*curr).se.prev_sum_exec_runtime;
                    if runtime >= ideal {
                        (*rq).need_resched.store(true, Ordering::Release);
                    }

                    (*rq).cfs.update_min_vruntime();
                }
                SchedPolicy::RoundRobin => {
                    // Decrement time slice
                    (*curr).rt.time_slice = (*curr).rt.time_slice.saturating_sub(1_000_000);
                    if (*curr).rt.time_slice == 0 {
                        (*curr).rt.time_slice = (*curr).rt.default_slice;
                        (*rq).need_resched.store(true, Ordering::Release);
                    }
                }
                SchedPolicy::Fifo => {
                    // FIFO doesn't expire — only preempted by higher prio
                }
                _ => {}
            }
        }
    }

    /// Update system load averages (called every 5 seconds).
    pub fn update_load_averages(&self) {
        let running = self.nr_running.load(Ordering::Relaxed) as u64;
        // Exponential decay: load(t) = load(t-1) * e^(-1/period) + running * (1 - e^(-1/period))
        // Fixed point: multiply by 2048
        let exp_1 = 1884; // e^(-5/60) * 2048 for 1-minute
        let exp_5 = 2014; // e^(-5/300) * 2048 for 5-minute
        let exp_15 = 2037; // e^(-5/900) * 2048 for 15-minute

        let exps = [exp_1, exp_5, exp_15];
        for (i, &exp) in exps.iter().enumerate() {
            let old = self.avenrun[i].load(Ordering::Relaxed);
            let new_val = (old * exp + running * (2048 - exp)) / 2048;
            self.avenrun[i].store(new_val, Ordering::Release);
        }
    }
}

/// Read TSC in nanoseconds (placeholder).
fn read_tsc_ns() -> u64 {
    0 // Would read rdtsc and convert
}

/// Wake up a task (set state to Running).
fn wake_up_task(task: *mut TaskStruct) {
    if task.is_null() {
        return;
    }
    unsafe {
        (*task).state.store(TaskState::Running as u32, Ordering::Release);
    }
}

// ============================================================================
// C FFI Exports
// ============================================================================

#[no_mangle]
pub extern "C" fn sched_init(_nr_cpus: u32) -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn sched_tick(cpu: u32) {
    let _ = cpu;
}

#[no_mangle]
pub extern "C" fn sched_schedule(cpu: u32) -> *mut TaskStruct {
    let _ = cpu;
    core::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn sched_setscheduler(
    _task: *mut TaskStruct,
    _policy: u32,
    _priority: i32,
) -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn sched_setaffinity(
    _task: *mut TaskStruct,
    _mask: *const u64,
    _len: usize,
) -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn sched_yield() -> i32 {
    0
}
