// =============================================================================
// Kernel Zxyphor — Rust IPC (Inter-Process Communication) Subsystem
// =============================================================================
//
// Sub-modules:
//   - message:   Message passing (mailbox) system
//   - semaphore: Counting semaphores
//   - futex:     Fast userspace mutual exclusion
// =============================================================================

pub mod message;
pub mod semaphore;
pub mod futex;
pub mod mqueue;
pub mod io_uring;
pub mod epoll;
pub mod rpc;
