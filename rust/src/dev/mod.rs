// =============================================================================
// Kernel Zxyphor — Rust Device & Block I/O Layer
// =============================================================================
// Provides a unified abstraction for block devices and I/O scheduling.
//
// Sub-modules:
//   - block:    Block device registry, request queue, I/O scheduler
//   - device:   Unified device model, device tree, hotplug
//   - bio:      Block I/O (bio) structure and completion
// =============================================================================

pub mod block;
pub mod device;
pub mod bio;
pub mod sysfs;
pub mod configfs;
pub mod virtio;
pub mod kmod;
pub mod kobject;
pub mod chardev;
pub mod notifier;
pub mod firmware;
pub mod tty;
