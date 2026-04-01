// =============================================================================
// Kernel Zxyphor — Completely Fair Scheduler (CFS)
// =============================================================================
// Linux-inspired CFS implementation:
//   - Virtual runtime (vruntime) tracking
//   - Red-black tree ordered by vruntime (simulated with sorted array)
//   - Nice values (-20 to +19) mapped to weight
//   - Load weight calculations
//   - Minimum granularity enforcement
//   - Sleeper fairness (vruntime credit for sleeping tasks)
//   - Group scheduling support
//   - CPU load tracking with geometric decay
//   - Pick-next-task in O(1) from leftmost node
//   - Task migration between run queues
// =============================================================================

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const MAX_TASKS: usize = 512;
pub const MAX_CPUS: usize = 64;
pub const NICE_TO_WEIGHT_SHIFT: u32 = 10;
pub const SCHED_MIN_GRANULARITY_NS: u64 = 750_000;   // 750us
pub const SCHED_LATENCY_NS: u64 = 6_000_000;          // 6ms
pub const SCHED_WAKEUP_GRANULARITY_NS: u64 = 1_000_000; // 1ms

// =============================================================================
// Nice → weight mapping (Linux sched_prio_to_weight)
// =============================================================================

const NICE_WEIGHT: [40]u32 = [
    /* -20 */ 88761, 71755, 56483, 46273, 36291,
    /* -15 */ 29154, 23254, 18705, 14949, 11916,
    /* -10 */ 9548,  7620,  6100,  4904,  3906,
    /*  -5 */ 3121,  2501,  1991,  1586,  1277,
    /*   0 */ 1024,  820,   655,   526,   423,
    /*   5 */ 335,   272,   215,   172,   137,
    /*  10 */ 110,   87,    70,    56,    45,
    /*  15 */ 36,    29,    23,    18,    15,
];

const NICE_INV_WEIGHT: [40]u32 = [
    /* -20 */ 48388, 59856, 76040, 92818, 118348,
    /* -15 */ 147320, 184698, 229616, 287308, 360437,
    /* -10 */ 449829, 563644, 704093, 875809, 1099582,
    /*  -5 */ 1376151, 1717300, 2157191, 2708050, 3363326,
    /*   0 */ 4194304, 5237765, 6557202, 8165337, 10153587,
    /*   5 */ 12820798, 15790321, 19976592, 24970740, 31350126,
    /*  10 */ 39045157, 49367440, 61356676, 76695844, 95443717,
    /*  15 */ 119304647, 148102320, 186737708, 238609294, 286331153,
];

pub fn nice_to_weight(nice: i8) u32 {
    let idx = (nice + 20).clamp(0, 39) as usize;
    NICE_WEIGHT[idx]
}

pub fn nice_to_inv_weight(nice: i8) u32 {
    let idx = (nice + 20).clamp(0, 39) as usize;
    NICE_INV_WEIGHT[idx]
}

// =============================================================================
// Scheduling entity
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskState {
    Running = 0,
    Runnable = 1,
    Sleeping = 2,
    Stopped = 3,
    Zombie = 4,
    Dead = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SchedPolicy {
    Normal = 0,     // CFS
    Fifo = 1,       // Real-time FIFO
    RoundRobin = 2, // Real-time RR
    Batch = 3,      // Batch processing
    Idle = 4,       // Idle-priority
}

pub struct SchedEntity {
    pub pid: u32,
    pub tid: u32,
    pub nice: i8,
    pub policy: SchedPolicy,
    pub state: TaskState,

    // CFS fields
    pub vruntime: u64,
    pub weight: u32,
    pub inv_weight: u32,
    pub exec_start_ns: u64,
    pub sum_exec_runtime_ns: u64,
    pub prev_sum_exec_runtime_ns: u64,

    // Real-time fields
    pub rt_priority: u8,      // 1-99 (higher = more priority)
    pub time_slice_ns: u64,
    pub remaining_slice_ns: u64,

    // CPU affinity
    pub cpu_affinity: u64,    // Bitmask
    pub last_cpu: u8,
    pub preferred_cpu: u8,
    pub migration_count: u32,

    // Process hierarchy
    pub ppid: u32,
    pub pgid: u32,
    pub sid: u32,

    // Resource usage
    pub user_time_ns: u64,
    pub system_time_ns: u64,
    pub voluntary_switches: u64,
    pub involuntary_switches: u64,

    // OOM killer
    pub oom_score: i32,
    pub oom_score_adj: i16,
    pub rss_pages: u32,       // Resident set size

    pub active: bool,
}

impl SchedEntity {
    pub const fn new() -> Self {
        Self {
            pid: 0,
            tid: 0,
            nice: 0,
            policy: SchedPolicy::Normal,
            state: TaskState::Dead,
            vruntime: 0,
            weight: 1024,
            inv_weight: 4194304,
            exec_start_ns: 0,
            sum_exec_runtime_ns: 0,
            prev_sum_exec_runtime_ns: 0,
            rt_priority: 0,
            time_slice_ns: SCHED_LATENCY_NS,
            remaining_slice_ns: SCHED_LATENCY_NS,
            cpu_affinity: u64::MAX,
            last_cpu: 0,
            preferred_cpu: 0,
            migration_count: 0,
            ppid: 0,
            pgid: 0,
            sid: 0,
            user_time_ns: 0,
            system_time_ns: 0,
            voluntary_switches: 0,
            involuntary_switches: 0,
            oom_score: 0,
            oom_score_adj: 0,
            rss_pages: 0,
            active: false,
        }
    }

    pub fn set_nice(&mut self, nice: i8) {
        self.nice = nice.clamp(-20, 19);
        self.weight = nice_to_weight(self.nice);
        self.inv_weight = nice_to_inv_weight(self.nice);
    }

    /// Calculate ideal runtime for this task based on weight and total load
    pub fn calc_ideal_runtime(&self, total_weight: u32, nr_running: u32) -> u64 {
        let period = if nr_running > (SCHED_LATENCY_NS / SCHED_MIN_GRANULARITY_NS) as u32 {
            (nr_running as u64) * SCHED_MIN_GRANULARITY_NS
        } else {
            SCHED_LATENCY_NS
        };

        if total_weight == 0 {
            return period;
        }

        // ideal_runtime = period * weight / total_weight
        (period as u128 * self.weight as u128 / total_weight as u128) as u64
    }

    /// Update vruntime based on actual execution time
    pub fn update_vruntime(&mut self, delta_exec_ns: u64) {
        // vruntime += delta_exec * NICE_0_WEIGHT / weight
        let vruntime_delta = if self.weight > 0 {
            (delta_exec_ns as u128 * 1024 / self.weight as u128) as u64
        } else {
            delta_exec_ns
        };
        self.vruntime += vruntime_delta;
        self.sum_exec_runtime_ns += delta_exec_ns;
    }

    /// Credit for sleeping (sleeper fairness)
    pub fn place_entity(&mut self, min_vruntime: u64, initial: bool) {
        let mut vruntime = min_vruntime;
        if initial {
            // New task gets half a scheduling period
            vruntime += SCHED_LATENCY_NS / 2;
        } else {
            // Waking sleeper: limit vruntime catchup
            let thresh = SCHED_LATENCY_NS;
            if min_vruntime > thresh && self.vruntime < min_vruntime - thresh {
                self.vruntime = min_vruntime - thresh;
                return;
            }
        }
        self.vruntime = core::cmp::max(self.vruntime, vruntime);
    }
}

// =============================================================================
// Per-CPU run queue
// =============================================================================

pub struct CfsRunQueue {
    pub cpu_id: u8,
    pub tasks: [u32; 128],    // PIDs of runnable tasks (sorted by vruntime)
    pub nr_running: u32,
    pub total_weight: u32,
    pub min_vruntime: u64,
    pub clock_ns: u64,        // CPU-local clock
    pub current_task: u32,    // PID of currently running task
    pub idle_timestamp_ns: u64,
    pub load: CpuLoad,
}

impl CfsRunQueue {
    pub const fn new(cpu: u8) -> Self {
        Self {
            cpu_id: cpu,
            tasks: [0u32; 128],
            nr_running: 0,
            total_weight: 0,
            min_vruntime: 0,
            clock_ns: 0,
            current_task: 0,
            idle_timestamp_ns: 0,
            load: CpuLoad::new(),
        }
    }

    /// Enqueue a task (insert sorted by vruntime)
    pub fn enqueue(&mut self, pid: u32, vruntime: u64, weight: u32, entities: &[SchedEntity]) {
        if self.nr_running as usize >= 128 {
            return;
        }

        // Find insertion point (sorted by vruntime)
        let mut pos = self.nr_running as usize;
        for i in 0..self.nr_running as usize {
            let task_pid = self.tasks[i];
            if let Some(ent) = entities.iter().find(|e| e.pid == task_pid && e.active) {
                if vruntime < ent.vruntime {
                    pos = i;
                    break;
                }
            }
        }

        // Shift right
        for i in ((pos + 1)..=(self.nr_running as usize)).rev() {
            if i < 128 {
                self.tasks[i] = self.tasks[i - 1];
            }
        }

        self.tasks[pos] = pid;
        self.nr_running += 1;
        self.total_weight += weight;
    }

    /// Dequeue a task
    pub fn dequeue(&mut self, pid: u32, weight: u32) {
        for i in 0..self.nr_running as usize {
            if self.tasks[i] == pid {
                for j in i..(self.nr_running as usize - 1) {
                    self.tasks[j] = self.tasks[j + 1];
                }
                self.nr_running -= 1;
                self.total_weight = self.total_weight.saturating_sub(weight);
                return;
            }
        }
    }

    /// Pick the next task (leftmost = lowest vruntime)
    pub fn pick_next(&self) -> Option<u32> {
        if self.nr_running == 0 {
            None
        } else {
            Some(self.tasks[0])
        }
    }

    /// Update min_vruntime
    pub fn update_min_vruntime(&mut self, current_vruntime: u64) {
        let mut vruntime = current_vruntime;
        if self.nr_running > 0 {
            // Min of current and leftmost task
            // (in a real impl, we'd look up leftmost vruntime from entities)
        }
        self.min_vruntime = core::cmp::max(self.min_vruntime, vruntime);
    }
}

// =============================================================================
// CPU load tracking
// =============================================================================

pub struct CpuLoad {
    pub load: [u64; 5],       // 1, 5, 15 tick, plus instant and long-term
    pub nr_running_avg: u64,  // Running average of nr_running
    pub utilization_pct: u32, // 0-100
}

impl CpuLoad {
    pub const fn new() -> Self {
        Self {
            load: [0u64; 5],
            nr_running_avg: 0,
            utilization_pct: 0,
        }
    }

    /// Update load with geometric decay
    pub fn update(&mut self, nr_running: u32, _now_ns: u64) {
        // Exponentially-weighted moving average
        let instant = (nr_running as u64) << 10;

        // Decay factors: 1/2, 1/4, 1/8, 1/16, 1/32
        for i in 0..5 {
            let decay_shift = i as u32 + 1;
            self.load[i] = self.load[i] - (self.load[i] >> decay_shift) + (instant >> decay_shift);
        }

        self.nr_running_avg = self.load[0] >> 10;
    }
}

// =============================================================================
// Global CFS scheduler
// =============================================================================

pub struct CfsScheduler {
    pub entities: [SchedEntity; MAX_TASKS],
    pub entity_count: usize,
    pub run_queues: [CfsRunQueue; MAX_CPUS],
    pub active_cpus: u32,
    pub total_tasks: AtomicU32,
    pub context_switches: AtomicU64,
    pub next_pid: AtomicU32,
}

impl CfsScheduler {
    pub const fn new() -> Self {
        Self {
            entities: [const { SchedEntity::new() }; MAX_TASKS],
            entity_count: 0,
            run_queues: [
                CfsRunQueue::new(0), CfsRunQueue::new(1),
                CfsRunQueue::new(2), CfsRunQueue::new(3),
                CfsRunQueue::new(4), CfsRunQueue::new(5),
                CfsRunQueue::new(6), CfsRunQueue::new(7),
                CfsRunQueue::new(8), CfsRunQueue::new(9),
                CfsRunQueue::new(10), CfsRunQueue::new(11),
                CfsRunQueue::new(12), CfsRunQueue::new(13),
                CfsRunQueue::new(14), CfsRunQueue::new(15),
                CfsRunQueue::new(16), CfsRunQueue::new(17),
                CfsRunQueue::new(18), CfsRunQueue::new(19),
                CfsRunQueue::new(20), CfsRunQueue::new(21),
                CfsRunQueue::new(22), CfsRunQueue::new(23),
                CfsRunQueue::new(24), CfsRunQueue::new(25),
                CfsRunQueue::new(26), CfsRunQueue::new(27),
                CfsRunQueue::new(28), CfsRunQueue::new(29),
                CfsRunQueue::new(30), CfsRunQueue::new(31),
                CfsRunQueue::new(32), CfsRunQueue::new(33),
                CfsRunQueue::new(34), CfsRunQueue::new(35),
                CfsRunQueue::new(36), CfsRunQueue::new(37),
                CfsRunQueue::new(38), CfsRunQueue::new(39),
                CfsRunQueue::new(40), CfsRunQueue::new(41),
                CfsRunQueue::new(42), CfsRunQueue::new(43),
                CfsRunQueue::new(44), CfsRunQueue::new(45),
                CfsRunQueue::new(46), CfsRunQueue::new(47),
                CfsRunQueue::new(48), CfsRunQueue::new(49),
                CfsRunQueue::new(50), CfsRunQueue::new(51),
                CfsRunQueue::new(52), CfsRunQueue::new(53),
                CfsRunQueue::new(54), CfsRunQueue::new(55),
                CfsRunQueue::new(56), CfsRunQueue::new(57),
                CfsRunQueue::new(58), CfsRunQueue::new(59),
                CfsRunQueue::new(60), CfsRunQueue::new(61),
                CfsRunQueue::new(62), CfsRunQueue::new(63),
            ],
            active_cpus: 1,
            total_tasks: AtomicU32::new(0),
            context_switches: AtomicU64::new(0),
            next_pid: AtomicU32::new(1),
        }
    }

    /// Create a new task
    pub fn create_task(&mut self, ppid: u32, nice: i8, policy: SchedPolicy) -> Option<u32> {
        for i in 0..MAX_TASKS {
            if !self.entities[i].active {
                let pid = self.next_pid.fetch_add(1, Ordering::Relaxed);
                self.entities[i] = SchedEntity::new();
                self.entities[i].pid = pid;
                self.entities[i].tid = pid;
                self.entities[i].ppid = ppid;
                self.entities[i].policy = policy;
                self.entities[i].state = TaskState::Runnable;
                self.entities[i].active = true;
                self.entities[i].set_nice(nice);

                // Place entity with min_vruntime credit
                let cpu = self.select_cpu(pid);
                self.entities[i].place_entity(self.run_queues[cpu as usize].min_vruntime, true);
                self.entities[i].last_cpu = cpu;

                self.run_queues[cpu as usize].enqueue(pid, self.entities[i].vruntime, self.entities[i].weight, &self.entities);
                self.total_tasks.fetch_add(1, Ordering::Relaxed);

                if i >= self.entity_count {
                    self.entity_count = i + 1;
                }

                return Some(pid);
            }
        }
        None
    }

    /// Select the best CPU for a task (load balancing)
    fn select_cpu(&self, _pid: u32) -> u8 {
        let mut best_cpu = 0u8;
        let mut min_load = u32::MAX;

        for i in 0..self.active_cpus as usize {
            let nr = self.run_queues[i].nr_running;
            if nr < min_load {
                min_load = nr;
                best_cpu = i as u8;
            }
        }
        best_cpu
    }

    /// Scheduler tick — update current task's vruntime
    pub fn tick(&mut self, cpu: u8, now_ns: u64) {
        let cpu_idx = cpu as usize;
        if cpu_idx >= MAX_CPUS { return; }

        let rq = &mut self.run_queues[cpu_idx];
        rq.clock_ns = now_ns;

        let current_pid = rq.current_task;
        if current_pid == 0 { return; }

        // Find the entity
        if let Some(entity) = self.entities.iter_mut().find(|e| e.pid == current_pid && e.active) {
            let delta = now_ns.saturating_sub(entity.exec_start_ns);
            entity.update_vruntime(delta);
            entity.exec_start_ns = now_ns;

            // Check if preemption needed
            let ideal = entity.calc_ideal_runtime(rq.total_weight, rq.nr_running);
            let actual = entity.sum_exec_runtime_ns - entity.prev_sum_exec_runtime_ns;
            if actual >= ideal {
                // Need to reschedule
                entity.involuntary_switches += 1;
            }
        }

        rq.load.update(rq.nr_running, now_ns);
    }

    /// Pick and switch to the next task
    pub fn schedule(&mut self, cpu: u8) -> Option<u32> {
        let cpu_idx = cpu as usize;
        if cpu_idx >= MAX_CPUS { return None; }

        let next_pid = self.run_queues[cpu_idx].pick_next()?;

        if next_pid != self.run_queues[cpu_idx].current_task {
            self.context_switches.fetch_add(1, Ordering::Relaxed);
            self.run_queues[cpu_idx].current_task = next_pid;
        }

        Some(next_pid)
    }

    /// Wake up a sleeping task
    pub fn wake_up(&mut self, pid: u32) {
        if let Some(entity) = self.entities.iter_mut().find(|e| e.pid == pid && e.active) {
            if entity.state == TaskState::Sleeping {
                entity.state = TaskState::Runnable;
                entity.voluntary_switches += 1;
                let cpu = entity.last_cpu as usize;
                entity.place_entity(self.run_queues[cpu].min_vruntime, false);
                self.run_queues[cpu].enqueue(pid, entity.vruntime, entity.weight, &self.entities);
            }
        }
    }

    /// Put a task to sleep
    pub fn sleep(&mut self, pid: u32) {
        if let Some(entity) = self.entities.iter_mut().find(|e| e.pid == pid && e.active) {
            entity.state = TaskState::Sleeping;
            let cpu = entity.last_cpu as usize;
            self.run_queues[cpu].dequeue(pid, entity.weight);
        }
    }

    /// Kill a task
    pub fn kill_task(&mut self, pid: u32) {
        if let Some(entity) = self.entities.iter_mut().find(|e| e.pid == pid && e.active) {
            entity.state = TaskState::Dead;
            entity.active = false;
            let cpu = entity.last_cpu as usize;
            self.run_queues[cpu].dequeue(pid, entity.weight);
            self.total_tasks.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Find least-important task for OOM killing
    pub fn oom_select(&self) -> Option<u32> {
        let mut worst_pid = 0u32;
        let mut worst_score = i32::MIN;

        for entity in &self.entities[..self.entity_count] {
            if !entity.active || entity.pid <= 1 { continue; }

            // OOM score: based on RSS + adjustment
            let score = (entity.rss_pages as i32) + entity.oom_score_adj as i32;
            if score > worst_score {
                worst_score = score;
                worst_pid = entity.pid;
            }
        }

        if worst_pid > 0 { Some(worst_pid) } else { None }
    }

    /// Load balance across CPUs
    pub fn load_balance(&mut self) {
        if self.active_cpus <= 1 { return; }

        // Find busiest and least busy CPUs
        let mut busiest = 0usize;
        let mut idlest = 0usize;
        let mut max_load = 0u32;
        let mut min_load = u32::MAX;

        for i in 0..self.active_cpus as usize {
            let nr = self.run_queues[i].nr_running;
            if nr > max_load { max_load = nr; busiest = i; }
            if nr < min_load { min_load = nr; idlest = i; }
        }

        // Only balance if difference is significant
        if max_load <= min_load + 1 { return; }

        // Move one task from busiest to idlest
        let task_count = self.run_queues[busiest].nr_running as usize;
        if task_count <= 1 { return; }

        // Pick the last task (highest vruntime, least urgent)
        let pid = self.run_queues[busiest].tasks[task_count - 1];

        if let Some(entity) = self.entities.iter_mut().find(|e| e.pid == pid && e.active) {
            // Check CPU affinity
            if entity.cpu_affinity & (1 << idlest) == 0 { return; }

            let weight = entity.weight;
            self.run_queues[busiest].dequeue(pid, weight);
            entity.last_cpu = idlest as u8;
            entity.migration_count += 1;
            entity.vruntime = core::cmp::max(
                entity.vruntime,
                self.run_queues[idlest].min_vruntime,
            );
            self.run_queues[idlest].enqueue(pid, entity.vruntime, weight, &self.entities);
        }
    }
}

static mut SCHEDULER: CfsScheduler = CfsScheduler::new();

pub unsafe fn scheduler() -> &'static mut CfsScheduler {
    &mut *core::ptr::addr_of_mut!(SCHEDULER)
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_sched_create_task(ppid: u32, nice: i8, policy: u8) -> i32 {
    let pol = match policy {
        0 => SchedPolicy::Normal,
        1 => SchedPolicy::Fifo,
        2 => SchedPolicy::RoundRobin,
        3 => SchedPolicy::Batch,
        4 => SchedPolicy::Idle,
        _ => return -1,
    };
    unsafe {
        match scheduler().create_task(ppid, nice, pol) {
            Some(pid) => pid as i32,
            None => -1,
        }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_sched_tick(cpu: u8, now_ns: u64) {
    unsafe { scheduler().tick(cpu, now_ns); }
}

#[no_mangle]
pub extern "C" fn zxyphor_sched_schedule(cpu: u8) -> u32 {
    unsafe { scheduler().schedule(cpu).unwrap_or(0) }
}

#[no_mangle]
pub extern "C" fn zxyphor_sched_wake(pid: u32) {
    unsafe { scheduler().wake_up(pid); }
}

#[no_mangle]
pub extern "C" fn zxyphor_sched_kill(pid: u32) {
    unsafe { scheduler().kill_task(pid); }
}

#[no_mangle]
pub extern "C" fn zxyphor_sched_balance() {
    unsafe { scheduler().load_balance(); }
}
