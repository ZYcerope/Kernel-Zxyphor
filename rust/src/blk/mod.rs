// =============================================================================
// Kernel Zxyphor — Rust Block I/O Layer
// =============================================================================
// Linux-quality block I/O subsystem:
//   - Request queue with plugging/unplugging
//   - Bio merging and splitting
//   - I/O priorities and deadline scheduling
//   - Multi-queue block layer (blk-mq)
//   - Tag-based request tracking
//   - I/O accounting
//   - Write barriers and flush support
//   - Discard/TRIM support
// =============================================================================

/// Subsystem modules
pub mod request;
pub mod blkmq;
pub mod elevator;
pub mod iosched;
