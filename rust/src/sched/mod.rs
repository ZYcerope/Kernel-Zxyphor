// =============================================================================
// Kernel Zxyphor — Process & Scheduler Subsystem (Rust)
// =============================================================================
// Scheduling policies and process management:
//   - CFS (Completely Fair Scheduler) with virtual runtime
//   - Real-time scheduling (FIFO and Round-Robin)
//   - Process priority and nice values
//   - CPU affinity masks
//   - Load balancing across CPUs
//   - Process groups and sessions
//   - Wait queues
//   - Cgroup-like resource control
//   - OOM killer scoring
// =============================================================================

pub mod cfs;
pub mod cgroup;
pub mod resource;
pub mod waitqueue;
pub mod perf;
pub mod bpf;
pub mod ftrace;
pub mod workqueue;
pub mod rcu;
pub mod hrtimer;
