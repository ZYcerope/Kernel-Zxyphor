// =============================================================================
// Kernel Zxyphor — Cooperative Kernel Task Executor
// =============================================================================
// A simple cooperative multitasking executor for kernel background tasks.
// This is NOT a preemptive scheduler — tasks voluntarily yield control.
//
// Use cases:
//   - Background garbage collection (slab/page cache)
//   - Deferred network processing
//   - Periodic maintenance (connection tracking cleanup, ARP cache expiry)
//   - Lazy writeback to disk
//
// Each task is a state machine with explicit yield points. The executor
// round-robins through ready tasks, executing each for one "step" before
// moving to the next.
// =============================================================================

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Maximum concurrent kernel tasks
const MAX_TASKS: usize = 128;

/// Task state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Task slot is free
    Free = 0,
    /// Task is ready to run
    Ready = 1,
    /// Task is currently executing
    Running = 2,
    /// Task is sleeping (waiting for a condition or timer)
    Sleeping = 3,
    /// Task has completed and can be cleaned up
    Completed = 4,
    /// Task has been cancelled
    Cancelled = 5,
}

/// Task step function: returns the next state for the task.
///
/// - Return `TaskState::Ready` to continue running on the next executor cycle
/// - Return `TaskState::Sleeping` to sleep until woken
/// - Return `TaskState::Completed` to finish
pub type TaskStepFn = extern "C" fn(context: usize) -> u8;

/// A kernel background task
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelTask {
    /// Task identifier
    pub id: u32,
    /// Current state
    pub state: TaskState,
    /// Step function (called each executor tick)
    pub step_fn: Option<TaskStepFn>,
    /// Opaque context
    pub context: usize,
    /// Task name (for debugging)
    pub name: [u8; 32],
    pub name_len: u8,
    /// Priority (0 = lowest, 255 = highest)
    pub priority: u8,
    /// Total steps executed
    pub steps_executed: u64,
    /// Wake-up tick (for sleeping tasks)
    pub wake_tick: u64,
    /// Creation timestamp
    pub created_at: u64,
}

impl KernelTask {
    pub const fn empty() -> Self {
        KernelTask {
            id: 0,
            state: TaskState::Free,
            step_fn: None,
            context: 0,
            name: [0u8; 32],
            name_len: 0,
            priority: 0,
            steps_executed: 0,
            wake_tick: 0,
            created_at: 0,
        }
    }
}

// =============================================================================
// Executor
// =============================================================================

/// The kernel task executor
pub struct Executor {
    tasks: [KernelTask; MAX_TASKS],
    next_id: u32,
    current_task: usize,
    current_tick: u64,
    total_steps: u64,
}

impl Executor {
    pub const fn new() -> Self {
        Executor {
            tasks: [KernelTask::empty(); MAX_TASKS],
            next_id: 1,
            current_task: 0,
            current_tick: 0,
            total_steps: 0,
        }
    }

    /// Create a new kernel task
    pub fn spawn(
        &mut self,
        name: &[u8],
        step_fn: TaskStepFn,
        context: usize,
        priority: u8,
    ) -> Option<u32> {
        // Find a free slot
        for i in 0..MAX_TASKS {
            if self.tasks[i].state == TaskState::Free {
                let id = self.next_id;
                self.next_id += 1;

                let name_len = if name.len() > 31 { 31 } else { name.len() };

                self.tasks[i] = KernelTask {
                    id,
                    state: TaskState::Ready,
                    step_fn: Some(step_fn),
                    context,
                    name: {
                        let mut n = [0u8; 32];
                        n[..name_len].copy_from_slice(&name[..name_len]);
                        n
                    },
                    name_len: name_len as u8,
                    priority,
                    steps_executed: 0,
                    wake_tick: 0,
                    created_at: self.current_tick,
                };

                return Some(id);
            }
        }
        None
    }

    /// Cancel a task by ID
    pub fn cancel(&mut self, task_id: u32) -> bool {
        for task in self.tasks.iter_mut() {
            if task.id == task_id && task.state != TaskState::Free {
                task.state = TaskState::Cancelled;
                return true;
            }
        }
        false
    }

    /// Wake a sleeping task
    pub fn wake(&mut self, task_id: u32) -> bool {
        for task in self.tasks.iter_mut() {
            if task.id == task_id && task.state == TaskState::Sleeping {
                task.state = TaskState::Ready;
                return true;
            }
        }
        false
    }

    /// Run one step of the executor: find the next ready task and execute
    /// one step of it. Returns true if a task was executed.
    pub fn step(&mut self) -> bool {
        self.current_tick += 1;

        // Wake up sleeping tasks whose wake_tick has passed
        for task in self.tasks.iter_mut() {
            if task.state == TaskState::Sleeping && task.wake_tick > 0 && task.wake_tick <= self.current_tick {
                task.state = TaskState::Ready;
                task.wake_tick = 0;
            }
        }

        // Clean up completed/cancelled tasks
        for task in self.tasks.iter_mut() {
            if task.state == TaskState::Completed || task.state == TaskState::Cancelled {
                *task = KernelTask::empty();
            }
        }

        // Find the next ready task (round-robin with priority boost)
        let start = self.current_task;
        let mut best_idx = MAX_TASKS;
        let mut best_priority = 0u8;

        for offset in 0..MAX_TASKS {
            let idx = (start + offset) % MAX_TASKS;
            let task = &self.tasks[idx];
            if task.state == TaskState::Ready && task.priority >= best_priority {
                best_idx = idx;
                best_priority = task.priority;
            }
        }

        if best_idx >= MAX_TASKS {
            return false; // No ready tasks
        }

        // Execute one step
        let task = &mut self.tasks[best_idx];
        task.state = TaskState::Running;

        if let Some(step_fn) = task.step_fn {
            let next_state = step_fn(task.context);

            task.state = match next_state {
                1 => TaskState::Ready,
                3 => TaskState::Sleeping,
                4 => TaskState::Completed,
                5 => TaskState::Cancelled,
                _ => TaskState::Ready,
            };

            task.steps_executed += 1;
            self.total_steps += 1;
        } else {
            task.state = TaskState::Completed;
        }

        self.current_task = (best_idx + 1) % MAX_TASKS;
        true
    }

    /// Run the executor for up to `max_steps` steps
    pub fn run(&mut self, max_steps: usize) -> usize {
        let mut count = 0;
        for _ in 0..max_steps {
            if !self.step() {
                break;
            }
            count += 1;
        }
        count
    }

    /// Count ready tasks
    pub fn ready_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| t.state == TaskState::Ready)
            .count()
    }

    /// Count all active tasks (not Free or Completed)
    pub fn active_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| {
                t.state != TaskState::Free
                    && t.state != TaskState::Completed
                    && t.state != TaskState::Cancelled
            })
            .count()
    }
}

// =============================================================================
// Global executor
// =============================================================================

static mut EXECUTOR: Executor = Executor::new();
static EXECUTOR_INITIALIZED: AtomicBool = AtomicBool::new(false);
static EXECUTOR_TOTAL_STEPS: AtomicU64 = AtomicU64::new(0);

// =============================================================================
// FFI exports
// =============================================================================

/// Initialize the executor
#[no_mangle]
pub extern "C" fn zxyphor_rust_executor_init() -> i32 {
    if EXECUTOR_INITIALIZED.load(Ordering::SeqCst) {
        return crate::ffi::error::FfiError::AlreadyExists.as_i32();
    }

    EXECUTOR_INITIALIZED.store(true, Ordering::SeqCst);
    crate::ffi::bridge::log_info("Rust kernel task executor initialized");

    crate::ffi::error::FfiError::Success.as_i32()
}

/// Spawn a new kernel task
#[no_mangle]
pub extern "C" fn zxyphor_rust_executor_spawn(
    name: *const u8,
    name_len: usize,
    step_fn: TaskStepFn,
    context: usize,
    priority: u8,
) -> i32 {
    let name_slice = if !name.is_null() && name_len > 0 {
        unsafe { core::slice::from_raw_parts(name, name_len) }
    } else {
        b"unnamed"
    };

    let executor = unsafe { &mut EXECUTOR };

    match executor.spawn(name_slice, step_fn, context, priority) {
        Some(id) => id as i32,
        None => crate::ffi::error::FfiError::NoMemory.as_i32(),
    }
}

/// Run the executor for up to max_steps
#[no_mangle]
pub extern "C" fn zxyphor_rust_executor_run(max_steps: u32) -> u32 {
    let executor = unsafe { &mut EXECUTOR };
    let count = executor.run(max_steps as usize);
    EXECUTOR_TOTAL_STEPS.fetch_add(count as u64, Ordering::Relaxed);
    count as u32
}

/// Cancel a task
#[no_mangle]
pub extern "C" fn zxyphor_rust_executor_cancel(task_id: u32) -> i32 {
    let executor = unsafe { &mut EXECUTOR };
    if executor.cancel(task_id) {
        crate::ffi::error::FfiError::Success.as_i32()
    } else {
        crate::ffi::error::FfiError::NotFound.as_i32()
    }
}

/// Wake a sleeping task
#[no_mangle]
pub extern "C" fn zxyphor_rust_executor_wake(task_id: u32) -> i32 {
    let executor = unsafe { &mut EXECUTOR };
    if executor.wake(task_id) {
        crate::ffi::error::FfiError::Success.as_i32()
    } else {
        crate::ffi::error::FfiError::NotFound.as_i32()
    }
}

/// Get executor statistics
#[repr(C)]
pub struct ExecutorStats {
    pub total_steps: u64,
    pub active_tasks: u32,
    pub ready_tasks: u32,
    pub current_tick: u64,
}

#[no_mangle]
pub extern "C" fn zxyphor_rust_executor_stats(out: *mut ExecutorStats) -> i32 {
    if out.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let executor = unsafe { &EXECUTOR };
    let stats = ExecutorStats {
        total_steps: EXECUTOR_TOTAL_STEPS.load(Ordering::Relaxed),
        active_tasks: executor.active_count() as u32,
        ready_tasks: executor.ready_count() as u32,
        current_tick: executor.current_tick,
    };

    unsafe { core::ptr::write(out, stats) };
    crate::ffi::error::FfiError::Success.as_i32()
}
